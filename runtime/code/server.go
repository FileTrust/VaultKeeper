package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	libp2p "github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	ma "github.com/multiformats/go-multiaddr"
)

// Serialize capacity-sensitive store admission/update to avoid concurrent
// requests passing stale capacity checks.
var storeCapacityMu sync.Mutex
var transferAdmission *transferAdmissionController
var transferAdmissionMu sync.Mutex

func transferController(cfg ServerConfig) *transferAdmissionController {
	transferAdmissionMu.Lock()
	defer transferAdmissionMu.Unlock()
	if transferAdmission == nil {
		transferAdmission = newTransferAdmissionController(cfg.Storage, cfg)
	}
	return transferAdmission
}

type requesterGuardState struct {
	failures      []time.Time
	cooldownUntil time.Time
}

var requesterGuardMu sync.Mutex
var requesterGuard = map[string]requesterGuardState{}

const (
	requesterMaxFailures = 3
	requesterFailWindow  = 30 * time.Minute
	requesterCooldown    = 30 * time.Minute
)

func requesterIDFromStream(s network.Stream) string {
	if s == nil || s.Conn() == nil {
		return "unknown"
	}
	return s.Conn().RemotePeer().String()
}

func requesterBlockedUntil(id string, now time.Time) (bool, time.Time) {
	requesterGuardMu.Lock()
	defer requesterGuardMu.Unlock()

	st, ok := requesterGuard[id]
	if !ok {
		return false, time.Time{}
	}
	if st.cooldownUntil.IsZero() || now.After(st.cooldownUntil) {
		st.cooldownUntil = time.Time{}
		requesterGuard[id] = st
		return false, time.Time{}
	}
	return true, st.cooldownUntil
}

func requesterFailWeight(sizeBytes int64) int {
	if sizeBytes <= 0 {
		return 1
	}
	const chunk = int64(256 * 1024 * 1024)
	w := int(sizeBytes/chunk) + 1
	if w > 5 {
		return 5
	}
	return w
}

func markRequesterFailure(id string, weight int, now time.Time) {
	if id == "" || id == "unknown" {
		return
	}
	if weight < 1 {
		weight = 1
	}

	requesterGuardMu.Lock()
	defer requesterGuardMu.Unlock()

	st := requesterGuard[id]
	kept := st.failures[:0]
	for _, t := range st.failures {
		if now.Sub(t) <= requesterFailWindow {
			kept = append(kept, t)
		}
	}
	st.failures = kept
	for i := 0; i < weight; i++ {
		st.failures = append(st.failures, now)
	}
	if len(st.failures) >= requesterMaxFailures {
		st.cooldownUntil = now.Add(requesterCooldown)
	}
	requesterGuard[id] = st
}

func markRequesterSuccess(id string, now time.Time) {
	if id == "" || id == "unknown" {
		return
	}

	requesterGuardMu.Lock()
	defer requesterGuardMu.Unlock()

	st, ok := requesterGuard[id]
	if !ok {
		return
	}
	kept := st.failures[:0]
	for _, t := range st.failures {
		if now.Sub(t) <= requesterFailWindow {
			kept = append(kept, t)
		}
	}
	st.failures = kept[:0]
	st.cooldownUntil = time.Time{}
	requesterGuard[id] = st
}

// loadOrGenIdentity loads the libp2p identity key from <storage>/identity.key,
// or generates and saves a new one if the file does not exist.
// This ensures the VK peer ID stays stable across restarts.
func loadOrGenIdentity(storageDir string) crypto.PrivKey {
	keyPath := filepath.Join(storageDir, "identity.key")
	credential := strings.TrimSpace(os.Getenv("FILETRUST_VK_IDENTITY_KEY_FILE"))
	if credential != "" {
		keyPath = credential
	}
	data, readErr := readOwnerPrivateFile(keyPath, 1024)
	if readErr == nil {
		priv, err := crypto.UnmarshalPrivateKey(data)
		if err != nil {
			log.Fatal("[identity] invalid saved peer identity; restore a backup instead of replacing it")
		}
		return priv
	}
	if credential != "" || !os.IsNotExist(readErr) {
		log.Fatal("[identity] cannot read the protected peer identity")
	}
	priv, _, err := crypto.GenerateKeyPair(crypto.Ed25519, -1)
	if err != nil {
		log.Fatalf("[identity] failed to generate identity key: %v", err)
	}
	data, err = crypto.MarshalPrivateKey(priv)
	if err != nil {
		log.Fatalf("[identity] failed to marshal identity key: %v", err)
	}
	if err := os.WriteFile(keyPath, data, 0600); err != nil {
		log.Printf("[identity] warning: could not save identity key to %s: %v", keyPath, err)
	} else {
		log.Printf("[identity] generated new peer identity, saved to %s", keyPath)
	}
	return priv
}

func storagePriceWeiForBytes(storageFee int64, sizeBytes int64, durationDays int64, suToWeiRate int64) *big.Int {
	if storageFee <= 0 || sizeBytes <= 0 || durationDays <= 0 || suToWeiRate <= 0 {
		return big.NewInt(0)
	}
	const bytesPerGB = int64(1_000_000_000)
	price := big.NewInt(storageFee)
	price.Mul(price, big.NewInt(sizeBytes))
	price.Mul(price, big.NewInt(durationDays))
	price.Mul(price, big.NewInt(suToWeiRate))
	denominator := big.NewInt(bytesPerGB)
	price.Add(price, new(big.Int).Sub(denominator, big.NewInt(1)))
	price.Div(price, denominator)
	return price
}

// prepareCapacityForServer verifies an existing exact snapshot but never builds
// a missing/stale one in the network server process. Capacity construction is
// durable background work owned by the proof daemon; keeping it out of startup
// lets every VK become reachable and register promptly on a shared host.
func prepareCapacityForServer(storage string, cfg ServerConfig) error {
	if cfg.CapacityBytes <= 0 {
		return nil
	}
	needsRebalance, detail, err := capacityNeedsRebalance(storage, cfg)
	if err != nil {
		// Capacity faults must close unsafe uploads through normal accounting, but
		// must not take the VK offline: existing users still need download and
		// deletion service. Persist/report the fault and let the daemon retry.
		if markerErr := setCapacityProofCatchupPhase(storage, "rebuild_failed", err.Error()); markerErr != nil {
			log.Printf("[capacity] startup snapshot inspection failed (%v); catch-up state also failed: %v", err, markerErr)
		} else {
			log.Printf("[capacity] startup snapshot inspection failed; server remains available for recovery: %v", err)
		}
		return nil
	}
	if !needsRebalance {
		log.Printf("[capacity] startup verified exact existing snapshot (%s)", detail)
		return nil
	}
	activeCapacity, activeErr := activeCapacitySectorMap(storage)
	if activeErr != nil {
		return fmt.Errorf("inspect active capacity sectors: %w", activeErr)
	}
	markCatchup := markCapacityProofCatchup
	if len(activeCapacity) == 0 {
		// A fresh VK must be reachable so all nodes can start fairly, but cannot
		// admit storage until its first exact snapshot is registered and proved.
		markCatchup = markInitialCapacityProofCatchup
	}
	if err := markCatchup(storage, "startup: "+detail); err != nil {
		return fmt.Errorf("queue startup capacity snapshot: %w", err)
	}
	log.Printf("[capacity] startup snapshot queued for background proof daemon (%s)", detail)
	return nil
}

func runServer(ctx context.Context, listen string, cfg ServerConfig) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := initStorage(cfg.Storage); err != nil {
		log.Fatal(err)
	}
	// This VK looks after its own log folder: zip finished logs, drop ones past
	// their retention. Transaction records outlive ordinary logs; read-call
	// dumps are debug noise and go sooner.
	StartLogArchiver(vkLogDir(cfg), LogArchiveOptions{
		MaxMB:          cfg.LogMaxMB,
		KeepDays:       cfg.LogKeepDays,
		MaxTotalMB:     cfg.LogMaxTotalMB,
		KeepDaysByName: map[string]int{"transactions": 90, "calls": 3},
	})
	if err := enforceDeploymentManifest(cfg.DeploymentManifestPath, cfg); err != nil {
		log.Fatalf("[deploy] %v", err)
	}
	// G.4B-LV0: the manifest is loaded and validated above; the deployed proof profile must
	// agree with this VK's local profile before any capacity work can begin. Terminal.
	if err := enforceDeployedProofProfile(cfg); err != nil {
		log.Fatalf("[capacity] deployed proof-profile preflight failed: %v", err)
	}
	transferAdmissionMu.Lock()
	transferAdmission = newTransferAdmissionController(cfg.Storage, cfg)
	transferAdmissionMu.Unlock()
	metrics := transferAdmission.snapshot()
	log.Printf("[transfer] limits uploads=%d downloads=%d queue=%d perIdentity=%d tempBytes=%d backgroundProofWorkers=%d..%d",
		metrics.MaxUploads, metrics.MaxDownloads, metrics.MaxQueued, metrics.MaxPerPeer,
		metrics.MaxTemporaryBytes, cfg.ProofBackgroundMinWorkers, cfg.ProofBackgroundMaxWorkers)
	startVKBackground(func() { runTransferStateGC(ctx.Done(), cfg.Storage, cfg) })
	startVKBackground(func() { runQuoteReservationReconciler(ctx.Done(), cfg) })
	startVKBackground(func() { runVKOperationalMetricsPublisher(ctx.Done(), cfg.Storage) })
	if cfg.CapacityBytes > 0 {
		if slotSize, err := resolvedCapacitySlotSize(cfg); err == nil {
			log.Printf("[capacity] config declared=%.1f MB slotSize=%.1f MB scheduling=continuous-checkpointed",
				float64(cfg.CapacityBytes)/1e6, float64(slotSize)/1e6)
		}
	}
	if err := prepareCapacityForServer(cfg.Storage, cfg); err != nil {
		log.Fatalf("[capacity] startup preparation failed: %v", err)
	}
	// Local partition assignment only. On-chain stale-partition cleanup must not
	// run here: after a prior load test the chain can still hold many partitions,
	// and that RPC/tx work easily exceeds the launcher peerId timeout (15s).
	if err := ensureAllPartitionAssignments(cfg.Storage, cfg); err != nil {
		log.Fatalf("[partition] assignment initialization failed: %v", err)
	}
	addr, err := ma.NewMultiaddr(listen)
	if err != nil {
		log.Fatal(err)
	}
	identity := loadOrGenIdentity(cfg.Storage)
	h, err := libp2p.New(libp2p.ListenAddrs(addr), libp2p.Identity(identity))
	if err != nil {
		log.Fatal(err)
	}

	// The v2 upload protocol performs no authorization at all -- it predates the
	// signed transfer handshake. Registering it unconditionally left an
	// unauthenticated write endpoint open on every keeper, next to the
	// authenticated one, for anyone who preferred to speak the older dialect.
	// It now exists only where an operator has asked for it.
	if cfg.AllowLegacyUnauthenticatedUploads {
		log.Printf("[store] WARNING: the unauthenticated v2 upload protocol is enabled; " +
			"anyone who can reach this keeper can write to it")
		installVKStreamHandler(h, StoreProtocol, func(s network.Stream) { handleStore(s, cfg) })
	}
	installVKStreamHandler(h, StoreProtocolV3, func(s network.Stream) { handleStoreV3(s, cfg) })
	installVKStreamHandler(h, GetProtocol, func(s network.Stream) { handleGet(s, cfg) })
	installVKStreamHandler(h, ProveProtocol, func(s network.Stream) { handleProve(s, cfg) })
	installVKStreamHandler(h, QuoteProtocol, func(s network.Stream) { handleQuote(s, cfg) })
	installVKStreamHandler(h, RenewProtocol, func(s network.Stream) { handleRenew(s, cfg) })
	installVKStreamHandler(h, DeleteProtocol, func(s network.Stream) { handleDelete(s, cfg) })
	installVKStreamHandler(h, HasPieceProtocol, func(s network.Stream) { handleHasPiece(s, cfg) })
	installVKStreamHandler(h, InfoProtocol, func(s network.Stream) { handleInfo(s, cfg) })
	installVKStreamHandler(h, RecoveryReceiptProtocol, func(s network.Stream) { handleRecoveryReceipt(s, cfg) })
	installVKStreamHandler(h, RecoveryVaultProtocol, func(s network.Stream) { handleRecoveryVault(s, cfg) })
	if cfg.ReachHelperEnabled {
		installVKStreamHandler(h, ReachRequestProtocol, newReachHelperService(cfg.PublicAddrAllowPrivate).handle)
	}
	if isAutoAdvertise(cfg) {
		detector := newPublicAddrDetector(cfg, h, hostTCPPort(h))
		installVKStreamHandler(h, ReachBackProtocol, detector.book.handle)
		activePublicAddr.Store(detector)
		startVKBackground(func() { detector.run(ctx) })
	}
	// A.2.5: publish the chain config the freeze oracle needs for on-chain reconciliation.
	activeFreezeChainConfig = cfg
	// A.2 startup barrier: run the pre-A.2 artifact migration and orphan sweep synchronously
	// BEFORE launching the reconciler (which can trigger deletion/recovery proofs). On failure
	// the gate stays closed so proving is disabled; the server still serves reads/uploads.
	// B.4: reservation recovery must complete before new upload allocation opens.
	if err := runSectorSlotRecoveryBarrier(cfg.Storage); err != nil {
		log.Printf("[reservation-recovery ✗] upload allocation stays closed: %v", err)
	}
	if err := runArtifactStartupBarrier(cfg.Storage); err != nil {
		log.Printf("[proof-snapshot] snapshot artifact startup barrier failed; proving disabled until resolved: %v", err)
	}
	startVKBackground(func() { runLifecycleReconciler(ctx, cfg) })
	startVKBackground(func() { runRegistryHeartbeat(ctx, cfg) })

	fmt.Println("FileTrust VK started")
	fmt.Println("VK peerId:", h.ID())
	fmt.Println("VK addresses:")
	for _, a := range h.Addrs() {
		fmt.Println(a.String() + "/p2p/" + h.ID().String())
	}
	advertised := advertisedMultiaddr(h, cfg)
	registryReady := false
	if cfg.VKRegistryContract != "" {
		fmt.Println("VaultKeeper registry:", cfg.VKRegistryContract)
		registryReady = registerSelfInRegistry(cfg, h.ID().String(), advertised)
		if registryReady {
			// Startup must publish the freshly recomputed chain/reservation view even
			// if another recovery goroutine attempted a sync moments earlier.
			forceAdmissionRegistrySync(cfg)
		} else {
			startVKBackground(func() { reconcileRegistryRegistration(ctx, h, cfg) })
		}
	}
	if cfg.CapacityBytes > 0 && cfg.ChainProofCmd != "" {
		if !registryReady {
			log.Printf("[capacity] startup declaration deferred until VaultKeeper registry eligibility is confirmed")
		} else if declareCapacityOnChain(cfg.ChainProofCmd, cfg.CapacityBytes) {
			if _, err := registerCurrentCapacityPartitionsOnChain(cfg); err != nil {
				if errors.Is(err, ErrCapacityPublicationDeferred) {
					log.Printf("[capacity] startup partition registration deferred until exact snapshot is ready: %v", err)
				} else {
					log.Printf("[capacity] partition registration warning: %v", err)
				}
			}
		}
		if err := cleanupStaleCapacityPartitionsOnChain(cfg.Storage, cfg); err != nil {
			log.Printf("[capacity] stale partition cleanup warning: %v", err)
		}
	}
	// Same rule as capacity cleanup: publish peerId first, then reconcile chain
	// leftovers in the background so launcher readiness is not blocked.
	// Runs for the life of the process, not once: a partition that empties after
	// startup would otherwise stay active on chain until the next restart, and the
	// delete that emptied it could then neither be proved nor retired. See
	// runStaleDataPartitionReconciler for the live evidence.
	startVKBackground(func() { runStaleDataPartitionReconciler(ctx.Done(), cfg) })
	if len(cfg.DiscoveryURLs) > 0 {
		fmt.Println("Discovery: enabled")
		fmt.Println("Discovery nodes:", strings.Join(cfg.DiscoveryURLs, ","))
		if isAutoAdvertise(cfg) {
			fmt.Println("Discovery multiaddr: automatic (published once proven; see storage/public_address.json)")
		} else {
			fmt.Println("Discovery multiaddr:", advertised)
		}
		if registryReady {
			startVKBackground(func() {
				startDiscoveryHeartbeat(ctx, cfg, h.ID().String(), func() string {
					return advertisedMultiaddr(h, cfg)
				})
			})
		} else {
			log.Printf("[discovery] heartbeat deferred until registry confirms peerId=%s", h.ID().String())
		}
	} else {
		fmt.Println("Discovery: disabled")
	}
	fmt.Println("DHT: disabled")
	fmt.Println("Bitswap: disabled")
	fmt.Println("Transfer security: libp2p secure transport")
	fmt.Println("Transfer mode: direct authorized peer connection")
	fmt.Println("Storage identifier: pieceRoot")
	fmt.Println("Sector mode: enabled")
	fmt.Println("Piece block size:", cfg.PieceBlockSize)
	if cfg.MaxPieceSizeBytes > 0 {
		fmt.Println("Max piece size bytes:", cfg.MaxPieceSizeBytes)
	} else {
		fmt.Println("Max piece size bytes: unlimited")
	}
	fmt.Println("Sector max pieces:", cfg.SectorMaxPieces)
	fmt.Println("Sector lifetime days:", cfg.SectorLifetimeDays)
	if cfg.AllowSectorExtend {
		fmt.Println("Sector extension: enabled")
	} else {
		fmt.Println("Sector extension: disabled")
	}
	if accessControlConfigured(cfg) {
		fmt.Println("ACL check: enabled")
		fmt.Println("ACL contract:", cfg.ACLAddress)
	} else if cfg.AllowUnauthenticatedReads {
		fmt.Println("ACL check: DISABLED BY REQUEST -- this keeper serves every piece it")
		fmt.Println("           holds to anyone who asks. Closed test networks only.")
	} else {
		fmt.Println("ACL check: not configured (missing --rpc-url or --acl-address)")
		fmt.Println("           Downloads are refused. Storage and proving continue, so")
		fmt.Println("           this keeper stays in good standing while it is fixed.")
	}
	if cfg.VKPrivKeyHex != "" && cfg.ChainID != 0 {
		fmt.Println("Receipt signing: enabled")
		fmt.Println("VK address:", cfg.VKAddress)
		fmt.Println("Chain ID:", cfg.ChainID)
	} else {
		fmt.Println("Receipt signing: disabled (missing --vk-private-key or --chain-id)")
	}
	if cfg.FileRegistrationContract != "" {
		fmt.Println("File registration: enabled")
		fmt.Println("FileRegistrationSC:", cfg.FileRegistrationContract)
	} else {
		fmt.Println("File registration: disabled (missing --file-registration-contract)")
	}
	select {
	case <-ctx.Done():
	case <-vkStop:
	}
	vkStreams.closeAndWait()
	cancel()
	vkBackground.closeAndWait()
}

func reconcileRegistryRegistration(ctx context.Context, h host.Host, cfg ServerConfig) {
	const retryInterval = 30 * time.Second
	timer := time.NewTimer(retryInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		advertised := advertisedMultiaddr(h, cfg)
		if !registerSelfInRegistry(cfg, h.ID().String(), advertised) {
			log.Printf("[vk_reg] registration still unconfirmed; retrying in %s", retryInterval)
			timer.Reset(retryInterval)
			continue
		}

		log.Printf("[vk_reg] registration reconciled after startup")
		maybeSyncAdmissionStatus(cfg)
		if cfg.CapacityBytes > 0 && cfg.ChainProofCmd != "" {
			if declareCapacityOnChain(cfg.ChainProofCmd, cfg.CapacityBytes) {
				if _, err := registerCurrentCapacityPartitionsOnChain(cfg); err != nil {
					if errors.Is(err, ErrCapacityPublicationDeferred) {
						log.Printf("[capacity] partition registration after registry recovery deferred: %v", err)
					} else {
						log.Printf("[capacity] partition registration after registry recovery warning: %v", err)
					}
				}
			}
		}
		if len(cfg.DiscoveryURLs) > 0 {
			startVKBackground(func() {
				startDiscoveryHeartbeat(ctx, cfg, h.ID().String(), func() string {
					return advertisedMultiaddr(h, cfg)
				})
			})
		}
		return
	}
}

// activePublicAddr is the running detector in --advertise-ip auto mode.
var activePublicAddr atomic.Pointer[publicAddrDetector]

// hostTCPPort is the TCP port the host listens on.
func hostTCPPort(h host.Host) int {
	for _, a := range h.Addrs() {
		if v, err := a.ValueForProtocol(ma.P_TCP); err == nil {
			if port, err := strconv.Atoi(v); err == nil && port > 0 {
				return port
			}
		}
	}
	return 0
}

// advertisedMultiaddr is the address published for this keeper. In auto mode it
// is empty until an address has been proven (public_address.go).
func advertisedMultiaddr(h host.Host, cfg ServerConfig) string {
	if isAutoAdvertise(cfg) {
		if d := activePublicAddr.Load(); d != nil {
			return d.Multiaddr()
		}
		return ""
	}
	ip := strings.TrimSpace(cfg.AdvertiseIP)
	if ip == "" {
		// Unchanged legacy behaviour for an empty setting: the first
		// non-loopback IPv4 address of this machine, unchecked.
		for _, addr := range h.Addrs() {
			candidate, err := addr.ValueForProtocol(ma.P_IP4)
			if err != nil || candidate == "0.0.0.0" || strings.HasPrefix(candidate, "127.") {
				continue
			}
			ip = candidate
			break
		}
		if ip == "" {
			ip = "127.0.0.1"
		}
	}
	return fmt.Sprintf("/ip4/%s/tcp/%d/p2p/%s", ip, hostTCPPort(h), h.ID())
}

func registerCurrentDataPartitionForSector(cfg ServerConfig, sectorID string) (string, error) {
	if cfg.ChainProofCmd == "" || cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 || sectorID == "" {
		return "", nil
	}
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return "", fmt.Errorf("register partition: list sectors: %w", err)
	}
	clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
	if clockErr != nil {
		return "", fmt.Errorf("register partition: proof clock: %w", clockErr)
	}
	partition, found := currentPartitionMetaForSectorAt(sectorID, sectors, cfg, clock.ChainTimestamp)
	if !found || partition.PartitionKind != PartitionKindData {
		return "", fmt.Errorf("register partition: data partition for sector %s not found", sectorID)
	}
	// An unresolved deletion OWNS this partition's next registration
	// (DeletionReleaseSC unresolvedOperationByPartition). Registering now would
	// present a successor manifest that still contains the piece the VK has already
	// declared deleted, and the contract correctly reverts with
	// "DR: deleted piece still present". Defer: the deletion removes the piece and
	// then registers CURRENT local state, which includes this store's sector.
	if owned, why, ownErr := pendingDeletionOwnsPartition(
		cfg.Storage, partition.DeadlineIndex, partition.PartitionIndex); ownErr != nil {
		return "", fmt.Errorf("register partition dl%d-pt%d: deletion ownership: %w",
			partition.DeadlineIndex, partition.PartitionIndex, ownErr)
	} else if owned {
		log.Printf("[partition] registration deferred dl=%d pt=%d: %s",
			partition.DeadlineIndex, partition.PartitionIndex, why)
		return "", errPartitionRegistrationDeferred
	}
	tx, err := registerConfiguredPartitionOnChain(cfg, partition)
	if err != nil {
		// TOCTOU: a deletion may have become the partition's owner between the
		// pre-check above and this transaction. Reclassify ONLY when the contract
		// gave the exact deleted-piece revert AND an authoritative re-read confirms
		// the deletion now owns this partition.
		if raced, why := registrationLostOwnershipRace(
			cfg.Storage, partition.DeadlineIndex, partition.PartitionIndex, err); raced {
			log.Printf("[partition] registration lost the ownership race dl=%d pt=%d: %s; "+
				"deferring to the deletion owner", partition.DeadlineIndex,
				partition.PartitionIndex, why)
			return "", errPartitionRegistrationDeferred
		}
		return "", fmt.Errorf("register partition dl%d-pt%d: %w", partition.DeadlineIndex, partition.PartitionIndex, err)
	}
	log.Printf("[partition] registered data partition  dl=%d pt=%d sectors=%d tx=%s",
		partition.DeadlineIndex, partition.PartitionIndex, len(partition.Sectors), tx)
	return tx, nil
}

func syncDataPartitionAfterDelete(cfg ServerConfig, sector SectorMeta) (string, error) {
	if allocatorLockHeldByCurrent() || partitionLockHeldByCurrent() || coordinationLockHeldByCurrent() {
		return "", fmt.Errorf("delete partition sync cannot start while an upload-path lock is held")
	}
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return "", nil
	}
	if cfg.ChainProofCmd == "" {
		return "", fmt.Errorf("chain proof command is required to update partition before deletion confirmation")
	}
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return "", fmt.Errorf("delete partition sync: list sectors: %w", err)
	}
	clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
	if clockErr != nil {
		return "", fmt.Errorf("delete partition sync: proof clock: %w", clockErr)
	}
	partition, found := currentPartitionMetaByCoordinatesAt(
		sectors, cfg, sector.DeadlineIndex, sector.PartitionIndex, PartitionKindData, clock.ChainTimestamp,
	)
	if found {
		tx, err := registerConfiguredPartitionOnChain(cfg, partition)
		if err != nil {
			return "", fmt.Errorf("delete partition sync: register dl%d-pt%d: %w", partition.DeadlineIndex, partition.PartitionIndex, err)
		}
		log.Printf("[partition] deletion updated data partition  dl=%d pt=%d sectors=%d tx=%s",
			partition.DeadlineIndex, partition.PartitionIndex, len(partition.Sectors), tx)
		return tx, nil
	}
	activePartitions, err := listActiveDataPartitionsOnChain(cfg.ChainProofCmd)
	if err != nil {
		return "", fmt.Errorf("delete partition sync: list active data partitions: %w", err)
	}
	active := false
	for _, candidate := range activePartitions {
		if candidate.DeadlineIndex == sector.DeadlineIndex && candidate.PartitionIndex == sector.PartitionIndex {
			active = true
			break
		}
	}
	if !active {
		log.Printf("[partition] deletion partition already absent/inactive dl=%d pt=%d",
			sector.DeadlineIndex, sector.PartitionIndex)
		return "", nil
	}
	tx, err := deactivatePartitionOnChain(cfg.ChainProofCmd, sector.DeadlineIndex, sector.PartitionIndex)
	if err != nil {
		return "", fmt.Errorf("delete partition sync: deactivate dl%d-pt%d: %w", sector.DeadlineIndex, sector.PartitionIndex, err)
	}
	log.Printf("[partition] deletion deactivated empty data partition  dl=%d pt=%d tx=%s",
		sector.DeadlineIndex, sector.PartitionIndex, tx)
	// The coordinate is gone from the chain's active set, so nothing can ever prove it again.
	// Any retry record for it is terminal-obsolete and must be retired here: the only other
	// path that would remove it is the activity-driven stale-partition sweep, which stops
	// running exactly when traffic stops — which is how Run 11 left a vault keeper degraded
	// permanently after its final delete.
	if retryErr := clearPartitionProofRetry(cfg.Storage, PartitionMeta{
		PartitionKind:  PartitionKindData,
		DeadlineIndex:  sector.DeadlineIndex,
		PartitionIndex: sector.PartitionIndex,
	}); retryErr != nil {
		log.Printf("[partition] retry-state clear warning dl=%d pt=%d: %v",
			sector.DeadlineIndex, sector.PartitionIndex, retryErr)
	}
	if retired, retireErr := retireProofJobsForDeadDataPartitions(cfg.Storage); retireErr != nil {
		log.Printf("[partition] scheduler-state retire warning dl=%d pt=%d: %v",
			sector.DeadlineIndex, sector.PartitionIndex, retireErr)
	} else if retired > 0 {
		log.Printf("[partition] retired %d terminal data proof scheduler job(s)", retired)
	}
	return tx, nil
}

func deletionPartitionProofSatisfied(cfg ServerConfig, partition PartitionMeta) (bool, error) {
	status, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition)
	if statusErr != nil {
		return false, statusErr
	}
	round := status.CurrentRound
	if !status.Active || !status.CurrentContentProven {
		return false, nil
	}
	if exactPartitionVersionAlreadyProven(status, partition, round) {
		_ = clearPartitionProofHealth(cfg.Storage, partition)
		return true, nil
	}
	satisfied := partitionMatchesChainContent(status, partition) &&
		sameRoot(status.LastProvenContentHash, status.ContentHash)
	if satisfied {
		_ = clearPartitionProofHealth(cfg.Storage, partition)
	}
	return satisfied, nil
}

func standaloneDeletionProofID(contentVersion uint64) (uint64, error) {
	if contentVersion == 0 || contentVersion >= standaloneDeletionProofFlag {
		return 0, fmt.Errorf("deletion successor content version is outside the proof domain: %d", contentVersion)
	}
	return standaloneDeletionProofFlag | contentVersion, nil
}

func frozenSnapshotIdentityMatches(
	snapshot *partitionProofSnapshot,
	status FrozenPartitionSnapshotStatus,
) bool {
	if snapshot == nil || !status.Exists || snapshot.ProofEpochID != status.ProofEpochID {
		return false
	}
	if snapshot.ContentVersion != 0 && snapshot.ContentVersion != status.ContentVersion {
		return false
	}
	if snapshot.Round != 0 && snapshot.Round != status.Round {
		return false
	}
	return snapshot.ChainContentHash == "" || sameRoot(snapshot.ChainContentHash, status.ContentHash)
}

// sealDeletionSuccessorSnapshot ensures the exact post-delete partition generation
// is immutably available for proof. Uploads are already excluded from this
// coordinate by pending-deletion sealing. ZK proving happens later and must not
// start while holding the partition lifecycle lock.
//
// Important: a capacity-epoch freeze of the same exact content already seals the
// bytes. Rebinding that freeze onto a standalone deletion epoch id is refused by
// the snapshot queue (capacity→standalone). Deletion must reuse that freeze and
// prove/confirm through the existing identity — not fight the capacity cutoff.
func sealDeletionSuccessorSnapshot(cfg ServerConfig, partition PartitionMeta, clock ProofClockStatus) error {
	// A.2 gate: sealing a deletion successor freezes a snapshot — a proof-affecting write.
	if gateErr := ensureProofArtifactWritesEnabled(); gateErr != nil {
		return gateErr
	}
	if cfg.ChainProofCmd == "" {
		return fmt.Errorf("deletion successor seal requires chain proof command")
	}
	satisfied, err := deletionPartitionProofSatisfied(cfg, partition)
	if err != nil {
		return err
	}
	if satisfied {
		return nil
	}
	status, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition)
	if statusErr != nil {
		return fmt.Errorf("deletion successor seal status: %w", statusErr)
	}
	if !status.Active || !partitionMatchesChainContent(status, partition) {
		return fmt.Errorf(
			"deletion successor seal: local partition is not the exact active chain successor dl=%d pt=%d",
			partition.DeadlineIndex, partition.PartitionIndex,
		)
	}

	// Prefer an existing exact-current freeze (capacity or standalone). This is
	// the common case when a capacity epoch already cut off the post-delete bytes.
	if sealed, sealErr := deletionSuccessorAlreadySealed(
		cfg, partition, status.ContentVersion, status.ContentHash,
	); sealErr != nil {
		return sealErr
	} else if sealed {
		return nil
	}

	proofEpochID, idErr := standaloneDeletionProofID(status.ContentVersion)
	if idErr != nil {
		return idErr
	}
	deadline := nextProofWindowDeadlineAt(
		clock.ChainTimestamp, clock.ProofPeriodSeconds, cfg.DeadlineCount,
	)
	for attempt := 0; attempt < 2; attempt++ {
		snapshot, destructive, prepErr := prepareFrozenPartitionSnapshot(
			cfg.Storage, partition, proofEpochID, clock.CurrentRound, deadline,
			cfg.DeadlineCount, cfg.PartitionMaxSectors, cfg.ChainProofCmd,
			clock.ChainTimestamp, true, nil,
		)
		if prepErr != nil {
			// Capacity cutoffs bind the same content under a non-standalone epoch.
			// Treat that as a successful seal so recovery can prove/confirm it.
			if sealed, sealErr := deletionSuccessorAlreadySealed(
				cfg, partition, status.ContentVersion, status.ContentHash,
			); sealErr != nil {
				return sealErr
			} else if sealed {
				log.Printf(
					"[delete] deletion successor already sealed under existing freeze dl=%d pt=%d version=%d (standalone bind deferred: %v)",
					partition.DeadlineIndex, partition.PartitionIndex, status.ContentVersion, prepErr,
				)
				return nil
			}
			return fmt.Errorf("deletion successor seal freeze: %w", prepErr)
		}
		if destructive {
			if abandonErr := abandonAndAdvancePartitionSnapshot(
				cfg.Storage, cfg.ChainProofCmd, snapshot,
				"deletion successor seal replaced obsolete frozen generation",
			); abandonErr != nil {
				return abandonErr
			}
			continue
		}
		if snapshot.ContentVersion == 0 {
			if sealed, sealErr := deletionSuccessorAlreadySealed(
				cfg, partition, status.ContentVersion, status.ContentHash,
			); sealErr != nil {
				return sealErr
			} else if sealed {
				return nil
			}
			return fmt.Errorf(
				"deletion successor seal did not bind contentVersion dl=%d pt=%d",
				partition.DeadlineIndex, partition.PartitionIndex,
			)
		}
		log.Printf(
			"[delete] sealed immutable deletion successor dl=%d pt=%d version=%d epoch=%d",
			partition.DeadlineIndex, partition.PartitionIndex,
			snapshot.ContentVersion, snapshot.ProofEpochID,
		)
		return nil
	}
	return fmt.Errorf(
		"deletion successor seal could not bind a stable frozen snapshot dl=%d pt=%d",
		partition.DeadlineIndex, partition.PartitionIndex,
	)
}

// deletionSuccessorAlreadySealed reports whether the exact post-delete content is
// already frozen on-chain (and locally, when a queue entry exists). A capacity
// cutoff freeze of the exact current version is a valid deletion seal.
func deletionSuccessorAlreadySealed(
	cfg ServerConfig,
	partition PartitionMeta,
	contentVersion uint64,
	contentHash string,
) (bool, error) {
	frozenStatus, frozenErr := frozenPartitionSnapshotStatusOnChain(cfg.ChainProofCmd, partition)
	if frozenErr != nil {
		return false, fmt.Errorf("deletion successor seal frozen status: %w", frozenErr)
	}
	if frozenStatus.Exists &&
		frozenStatus.ContentVersion == contentVersion &&
		frozenStatus.ContentVersion != 0 &&
		sameRoot(frozenStatus.ContentHash, contentHash) {
		log.Printf(
			"[delete] reuse existing frozen deletion successor dl=%d pt=%d version=%d epoch=%d",
			partition.DeadlineIndex, partition.PartitionIndex,
			frozenStatus.ContentVersion, frozenStatus.ProofEpochID,
		)
		return true, nil
	}
	queue, found, queueErr := readPartitionProofSnapshotQueue(
		cfg.Storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
	)
	if queueErr != nil {
		return false, queueErr
	}
	if found && queue.Frozen != nil &&
		samePartitionSnapshotContent(queue.Frozen, partition) &&
		queue.Frozen.ProofEpochID != 0 {
		versionOK := queue.Frozen.ContentVersion == 0 ||
			queue.Frozen.ContentVersion == contentVersion
		hashOK := queue.Frozen.ChainContentHash == "" ||
			sameRoot(queue.Frozen.ChainContentHash, contentHash)
		if versionOK && hashOK {
			log.Printf(
				"[delete] reuse local frozen deletion successor dl=%d pt=%d version=%d epoch=%d",
				partition.DeadlineIndex, partition.PartitionIndex,
				contentVersion, queue.Frozen.ProofEpochID,
			)
			return true, nil
		}
	}
	return false, nil
}

// proveDeletionPartitionSnapshot drains any older immutable capacity cutoff for
// this partition, then proves the exact live deletion successor in the reserved
// standalone proof domain. It never reports success from an error string: the
// caller still verifies the exact current proof through StorageProofSC.
func proveDeletionPartitionSnapshot(
	cfg ServerConfig,
	partition PartitionMeta,
	initialClock ProofClockStatus,
) error {
	epoch, err := capacityProofStatusOnChain(cfg.ChainProofCmd)
	if err != nil {
		return fmt.Errorf("delete snapshot proof capacity status: %w", err)
	}
	if err := reconcileInactiveEpochSnapshotQueues(cfg.Storage, cfg.ChainProofCmd, epoch); err != nil {
		return fmt.Errorf("delete snapshot proof queue reconciliation: %w", err)
	}

	clock := initialClock
	// One queue contains at most a frozen cutoff plus one coalesced successor.
	// Three passes cover retirement/proof of the cutoff and proof of the exact
	// successor while remaining bounded if foreground traffic keeps changing it.
	for pass := 0; pass < 3; pass++ {
		if pass > 0 {
			clock, err = proofClockStatusOnChain(cfg.ChainProofCmd)
			if err != nil {
				return fmt.Errorf("delete snapshot proof clock: %w", err)
			}
		}
		current, statusErr := partitionVersionStatusOnChain(cfg.ChainProofCmd, partition)
		if statusErr != nil {
			return fmt.Errorf("delete snapshot proof partition status: %w", statusErr)
		}
		if !current.Active || !partitionMatchesChainContent(current, partition) {
			return fmt.Errorf("delete snapshot proof local partition is not the exact active chain successor")
		}
		if current.CurrentContentProven && sameRoot(current.LastProvenContentHash, current.ContentHash) {
			return nil
		}

		proofEpochID, idErr := standaloneDeletionProofID(current.ContentVersion)
		if idErr != nil {
			return idErr
		}
		proofRound := clock.CurrentRound
		proofPartition := partition
		requireCurrentContent := true

		frozenStatus, frozenErr := frozenPartitionSnapshotStatusOnChain(cfg.ChainProofCmd, partition)
		if frozenErr != nil {
			return fmt.Errorf("delete snapshot proof frozen status: %w", frozenErr)
		}
		if frozenStatus.Exists {
			proofEpochID = frozenStatus.ProofEpochID
			proofRound = frozenStatus.Round
			requireCurrentContent = frozenStatus.Current &&
				frozenStatus.ContentVersion == current.ContentVersion &&
				sameRoot(frozenStatus.ContentHash, current.ContentHash)

			queue, found, queueErr := readPartitionProofSnapshotQueue(
				cfg.Storage, partition.PartitionKind, partition.DeadlineIndex, partition.PartitionIndex,
			)
			if queueErr != nil {
				return queueErr
			}
			var frozenLocal *partitionProofSnapshot
			if found && frozenSnapshotIdentityMatches(queue.Frozen, frozenStatus) {
				frozenLocal = queue.Frozen
				proofPartition = queue.Frozen.Partition
			}

			// A standalone deletion proof that became historical cannot release
			// anything. Retire it immediately and bind the latest successor.
			// A destructive capacity cutoff is likewise invalid by protocol.
			destructive := !requireCurrentContent && frozenLocal != nil &&
				!partitionTransitionRetainsFrozenData(frozenLocal.Partition, partition)
			if !requireCurrentContent &&
				(proofEpochID&standaloneDeletionProofFlag != 0 || destructive || frozenLocal == nil) {
				stale := partitionProofSnapshot{
					Partition: proofPartition, ProofEpochID: proofEpochID,
					ContentVersion: frozenStatus.ContentVersion, Round: proofRound,
					ChainContentHash: frozenStatus.ContentHash,
				}
				if frozenLocal != nil {
					stale = *frozenLocal
				}
				if abandonErr := abandonAndAdvancePartitionSnapshot(
					cfg.Storage, cfg.ChainProofCmd, stale,
					"deletion requires a newer exact successor",
				); abandonErr != nil {
					return abandonErr
				}
				continue
			}
		}

		deadline := nextProofWindowDeadlineAt(
			clock.ChainTimestamp, clock.ProofPeriodSeconds, cfg.DeadlineCount,
		)
		proofErr := provePartitionSnapshotCandidate(
			cfg.Storage, proofPartition, proofEpochID, proofRound,
			cfg.DeadlineCount, cfg.PartitionMaxSectors,
			cfg.PartitionProverCmd, cfg.ChainProofCmd,
			"deletion-successor", deadline, clock.ChainTimestamp,
			true, requireCurrentContent,
			// A standalone deletion-successor proof is NOT capacity campaign work, so it
			// carries no C.1 capacity duration class.
			"",
		)
		if errors.Is(proofErr, ErrPartitionProofSnapshotInvalidated) {
			continue
		}
		if proofErr != nil {
			return proofErr
		}
	}
	return fmt.Errorf("delete snapshot proof successor changed repeatedly; durable lifecycle will retry")
}

func proveDeletionDataPartition(cfg ServerConfig, sector SectorMeta, partition PartitionMeta) (string, error) {
	satisfied, err := deletionPartitionProofSatisfied(cfg, partition)
	if err != nil {
		return "", err
	}
	if satisfied {
		log.Printf("[partition] deletion proof already satisfied dl=%d pt=%d",
			partition.DeadlineIndex, partition.PartitionIndex)
		return "", nil
	}
	var tx string
	if cfg.DeterministicChallenge {
		clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
		if clockErr != nil {
			err = clockErr
		} else {
			err = proveDeletionPartitionSnapshot(cfg, partition, clock)
		}
	} else {
		tx, err = proveDataPartitionAfterDelete(cfg, sector)
	}
	if err == nil {
		satisfied, checkErr := deletionPartitionProofSatisfied(cfg, partition)
		if checkErr == nil && satisfied {
			log.Printf("[partition] deletion proved exact current data partition dl=%d pt=%d",
				partition.DeadlineIndex, partition.PartitionIndex)
			return tx, nil
		}
		if checkErr != nil {
			return "", checkErr
		}
		err = fmt.Errorf("delete partition proof completed without an exact current on-chain proof")
	}
	satisfied, checkErr := deletionPartitionProofSatisfied(cfg, partition)
	if checkErr == nil && satisfied {
		log.Printf("[partition] deletion proof error treated as satisfied dl=%d pt=%d: %v",
			partition.DeadlineIndex, partition.PartitionIndex, err)
		return "", nil
	}
	return "", err
}

func proveDataPartitionAfterDelete(cfg ServerConfig, sector SectorMeta) (string, error) {
	if cfg.DeadlineCount <= 0 || cfg.PartitionMaxSectors <= 0 {
		return "", nil
	}
	if cfg.ChainProofCmd == "" {
		return "", fmt.Errorf("chain proof command is required to prove partition before deletion confirmation")
	}
	if cfg.PartitionProverCmd == "" {
		return "", fmt.Errorf("partition prover command is required to prove partition before deletion confirmation")
	}
	clock, clockErr := proofClockStatusOnChain(cfg.ChainProofCmd)
	if clockErr != nil {
		return "", fmt.Errorf("delete partition proof clock: %w", clockErr)
	}
	sectors, err := listSectors(cfg.Storage)
	if err != nil {
		return "", fmt.Errorf("delete partition proof: list sectors: %w", err)
	}
	partition, found := currentPartitionMetaByCoordinatesAt(
		sectors, cfg, sector.DeadlineIndex, sector.PartitionIndex, PartitionKindData, clock.ChainTimestamp,
	)
	if !found {
		return "", nil
	}
	round := clock.CurrentRound
	tx, err := provePartitionWithChainIntent(
		cfg.Storage,
		partition,
		round,
		cfg.ChallengeCount,
		cfg.DeadlineCount,
		cfg.PartitionMaxSectors,
		cfg.PartitionProverCmd,
		cfg.ChainProofCmd,
		cfg.DeterministicChallenge,
		true,
		nextProofWindowDeadlineAt(clock.ChainTimestamp, clock.ProofPeriodSeconds, cfg.DeadlineCount),
		clock.ChainTimestamp,
		"deletion",
	)
	if err != nil {
		return "", fmt.Errorf("delete partition proof dl%d-pt%d: %w", partition.DeadlineIndex, partition.PartitionIndex, err)
	}
	log.Printf("[partition] deletion proved current data partition  dl=%d pt=%d sectors=%d tx=%s",
		partition.DeadlineIndex, partition.PartitionIndex, len(partition.Sectors), tx)
	return tx, nil
}

func handleStore(s network.Stream, cfg ServerConfig) {
	handleStoreProtocol(s, cfg, false)
}

func handleStoreV3(s network.Stream, cfg ServerConfig) {
	handleStoreProtocol(s, cfg, true)
}

func handleStoreProtocol(s network.Stream, cfg ServerConfig, admissionHandshake bool) {
	defer s.Close()
	requesterID := requesterIDFromStream(s)
	var req StoreReq
	now := time.Now().UTC()
	if blocked, until := requesterBlockedUntil(requesterID, now); blocked {
		writeJSON(s, StoreResp{OK: false, Err: fmt.Sprintf("requester temporarily blocked until %s", until.Format(time.RFC3339))})
		return
	}
	failStore := func(errMsg string, weight int) {
		markRequesterFailure(requesterID, weight, time.Now().UTC())
		writeJSON(s, StoreResp{OK: false, Err: errMsg})
	}
	failStoreForError := func(prefix string, err error, weight int) {
		message := prefix + err.Error()
		if errors.Is(err, ErrRPCUnavailable) {
			log.Printf("[store ←] RETRYABLE %s", message)
			writeJSON(s, StoreResp{OK: false, Err: "temporary blockchain RPC failure — retry the same transfer: " + err.Error()})
			return
		}
		failStore(message, weight)
	}
	rejectStore := func(errMsg string) {
		if strings.Contains(errMsg, "insufficient unreserved capacity") ||
			strings.Contains(errMsg, "insufficient proved capacity") ||
			strings.Contains(errMsg, "insufficient physical capacity") ||
			strings.Contains(errMsg, "admission margin would be violated") ||
			strings.Contains(errMsg, "admission closed") {
			// Publish a real state transition immediately, but do not let repeated
			// oversized requests force identical registry transactions.
			maybeSyncAdmissionStatus(cfg)
		}
		failureSignature := ""
		if req.PaymentCommitment != "" && cfg.CapacityBytes > 0 {
			if creds, loadErr := LoadPaymentCredentials(cfg.Storage, req.PaymentCommitment); loadErr == nil {
				if key, keyErr := ParseVKPrivKey(cfg.VKPrivKeyHex); keyErr == nil {
					failureSignature, _ = signAdmissionFailure(
						key, cfg.ChainID, cfg.VKAddress, cfg.VKEscrowContract,
						req.PaymentCommitment, creds.RegistrationCommitment,
					)
				}
			}
		}
		writeJSON(s, StoreResp{
			OK: false, Err: errMsg, AdmissionFailureSignature: failureSignature,
		})
	}

	r := bufio.NewReader(s)
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		failStore(err.Error(), 1)
		return
	}
	if req.Size <= 0 {
		failStore("invalid piece size", 1)
		return
	}
	var existingStoredMeta *PieceMeta
	if admissionHandshake {
		knownTransfer, matchErr := existingStoreTransferMatches(cfg.Storage, req)
		if matchErr != nil {
			failStore("resumable transfer binding failed: "+matchErr.Error(), 1)
			return
		}
		if err := authorizeStoreRequest(cfg, req, knownTransfer); err != nil {
			failStore("upload authorization failed: "+err.Error(), 1)
			return
		}
		// Reject a commitment made with different Merkle parameters before any
		// durable transfer state, reservation activation, or piece bytes are
		// accepted. The same check is repeated after receipt as defence in depth.
		if err := validateExpectedPieceCommitmentParameters(req, cfg.PieceBlockSize); err != nil {
			failStore("upload authorization failed: "+err.Error(), 1)
			return
		}
		// Invalid new requests must not create durable control files. Existing
		// transfers are read-only here so a completed response can still be
		// recovered without repeating escrow or chain work.
		if knownTransfer {
			record, found, loadErr := loadStoreTransferRecord(cfg.Storage, req.TransferID)
			if loadErr != nil || !found {
				if loadErr == nil {
					loadErr = fmt.Errorf("durable transfer record disappeared")
				}
				failStore("resumable transfer state failed: "+loadErr.Error(), 1)
				return
			}
			if record.Status == "completed" && record.CompletedStore != nil {
				response := *record.CompletedStore
				response.OK = true
				response.Complete = true
				response.TransferID = req.TransferID
				markRequesterSuccess(requesterID, time.Now().UTC())
				writeJSON(s, response)
				return
			}
			if meta, ok := findStoredPieceByStoreReq(cfg.Storage, req); ok &&
				meta.SectorID != "" && meta.TransferID == req.TransferID {
				verified, _, verifyErr := verifyStoredPiece(cfg.Storage, meta.PieceRoot)
				if verifyErr != nil || !verified {
					failStore("existing transfer piece failed integrity verification", 1)
					return
				}
				existingStoredMeta = &meta
				log.Printf("[transfer] resuming finalization for already stored transfer=%s pieceRoot=%s",
					req.TransferID, truncate(meta.PieceRoot, 18))
			}
		}
		req.Resume = true
	}
	if cfg.MaxPieceSizeBytes > 0 && req.Size > cfg.MaxPieceSizeBytes {
		failStore(fmt.Sprintf("piece size %d exceeds VK maxPieceSizeBytes %d", req.Size, cfg.MaxPieceSizeBytes), 1)
		return
	}
	if cfg.CapacityBytes > 0 && !admissionHandshake {
		failStore("capacity-backed storage requires the resumable store/3 protocol", 1)
		return
	}
	if cfg.CapacityBytes > 0 && req.PaymentCommitment == "" {
		failStore("capacity-backed storage requires a durable quoted reservation", 1)
		return
	}
	if existingStoredMeta == nil && !admissionHandshake {
		if err := ensureAdmissionCapacityAvailableForUnreservedPiece(
			cfg.Storage, cfg.CapacityBytes, req.Size, cfg.ZKBlockSize, admissionMarginBytes(cfg),
		); err != nil {
			rejectStore(err.Error())
			return
		}
	}
	pieceFormat, err := normalizeStorePieceFormat(req.FileFormat)
	if err != nil {
		failStore(err.Error(), 1)
		return
	}
	req.FileFormat = pieceFormat
	// Enforce maxServiceDays: reject pieces whose serviceEnd exceeds the VK's limit.
	if cfg.MaxServiceDays > 0 && req.ServiceEnd > 0 {
		maxEnd := time.Now().UTC().Unix() + int64(cfg.MaxServiceDays)*86400
		if req.ServiceEnd > maxEnd {
			log.Printf("[store ←] REJECTED serviceEnd=%d exceeds maxServiceDays=%d  fileId=%s",
				req.ServiceEnd, cfg.MaxServiceDays, req.FileID)
			failStore(fmt.Sprintf("serviceEnd exceeds VK maxServiceDays (%d)", cfg.MaxServiceDays), 1)
			return
		}
	}

	// ── Quote-linked escrow flow ──────────────────────────────────────────────
	// When DO pre-obtained a quote and already deposited escrow, they provide
	// paymentCommitment in the request. VK verifies deposit on-chain and checks
	// that the file size matches what was agreed in the quote.
	var pregenCreds *PaymentCredentials
	pregenRegistrationCommitment := ""
	var capacityActivation *quoteActivationLease
	if req.PaymentCommitment != "" {
		creds, credsErr := LoadPaymentCredentials(cfg.Storage, req.PaymentCommitment)
		if credsErr != nil {
			log.Printf("[store ←] REJECTED paymentCommitment=%s not found locally: %v",
				truncate(req.PaymentCommitment, 18), credsErr)
			failStore("paymentCommitment not found — request a quote first", 1)
			return
		}
		// Enforce agreed size: reject if DO sends a different size than quoted.
		if req.Size != creds.PieceSize {
			log.Printf("[store ←] REJECTED size=%d != agreedSize=%d  pc=%s",
				req.Size, creds.PieceSize, truncate(req.PaymentCommitment, 18))
			failStore(fmt.Sprintf("file size %d does not match quoted size %d", req.Size, creds.PieceSize), 1)
			return
		}
		// Verify escrow deposit on-chain (view call — no gas, no trace).
		//
		// Fail closed, for the same reason as the ownership check above. This
		// used to run only when an escrow contract and an RPC URL happened to be
		// configured, so a keeper missing either one stored every piece it was
		// offered without ever confirming it had been paid -- free storage for
		// the whole network, announced nowhere, until someone noticed the disk.
		if !escrowVerificationConfigured(cfg) {
			if !cfg.AllowUnverifiedPayments {
				failStore("payment cannot be verified on this vault keeper: "+
					"no escrow contract or RPC URL is configured", 1)
				return
			}
		} else {
			registrationDeadline, verifyErr := verifyEscrowDeposit(cfg, creds)
			if verifyErr != nil {
				log.Printf("[store ←] REJECTED escrow verification failed  pc=%s: %v",
					truncate(req.PaymentCommitment, 18), verifyErr)
				failStoreForError("escrow deposit verification failed: ", verifyErr, 1)
				return
			}
			creds.RegistrationDeadline = registrationDeadline
			if reservationErr := validateQuoteReservationForStore(cfg, req, creds); reservationErr != nil {
				failStoreForError("capacity reservation verification failed: ", reservationErr, 1)
				return
			}
			if saveErr := SaveQuoteCredentials(cfg.Storage, creds); saveErr != nil {
				failStore("persist verified escrow deadline: "+saveErr.Error(), 1)
				return
			}
			log.Printf("[store ←] escrow verified  pc=%s  amount=%s", truncate(req.PaymentCommitment, 18), creds.AgreedPriceWei)
		}
		pregenCreds = &creds
		pregenRegistrationCommitment = creds.RegistrationCommitment
		log.Printf("[store ←] quote-linked  pc=%s  agreedSize=%d", truncate(req.PaymentCommitment, 18), creds.PieceSize)
	}

	// Validate lifecycle secrets before receiving bytes. New FileRegistration-backed
	// stores must be DO-authorized for deletion; legacy records remain supported
	// only through already-existing on-chain registrations.
	commitmentNonce := strings.TrimSpace(req.CommitmentNonce)
	if commitmentNonce != "" {
		raw := strings.TrimPrefix(commitmentNonce, "0x")
		if len(raw) != 64 {
			failStore("commitmentNonce must be a 32-byte hex value", 1)
			return
		}
		if _, decErr := hex.DecodeString(raw); decErr != nil {
			failStore("commitmentNonce must be valid hex", 1)
			return
		}
		if raw == strings.Repeat("0", 64) {
			failStore("commitmentNonce must not be zero", 1)
			return
		}
		if !strings.HasPrefix(commitmentNonce, "0x") {
			commitmentNonce = "0x" + raw
		}
	}
	if commitmentNonce == "" {
		gen, genErr := randomNonce()
		if genErr != nil {
			failStore("commitment nonce generation failed: "+genErr.Error(), 1)
			return
		}
		commitmentNonce = gen
	}

	deletionAuthHash := strings.TrimSpace(req.DeletionAuthHash)
	if deletionAuthHash != "" {
		raw := strings.TrimPrefix(deletionAuthHash, "0x")
		if len(raw) != 64 {
			failStore("deletionAuthHash must be a 32-byte hex value", 1)
			return
		}
		if _, decErr := hex.DecodeString(raw); decErr != nil {
			failStore("deletionAuthHash must be valid hex", 1)
			return
		}
		if raw == strings.Repeat("0", 64) {
			failStore("deletionAuthHash must not be zero", 1)
			return
		}
		if !strings.HasPrefix(deletionAuthHash, "0x") {
			deletionAuthHash = "0x" + raw
		}
	}
	if cfg.FileRegistrationContract != "" && deletionAuthHash == "" {
		failStore("deletionAuthHash is required when FileRegistration is configured", 1)
		return
	}

	log.Printf("[store ←] size=%d fileId=%s serviceEnd=%d", req.Size, req.FileID, req.ServiceEnd)
	if req.FileID != "" && cfg.RPCURL != "" && cfg.ACLAddress != "" {
		exists, aclErr := aclFilePolicyExists(cfg.RPCURL, cfg.ACLAddress, req.FileID)
		if aclErr != nil {
			failStore("ACL policy check failed: "+aclErr.Error(), 1)
			return
		}
		if !exists {
			failStore("fileId has no registered policy in ACL", 1)
			return
		}
	}
	if admissionHandshake {
		if _, stateErr := loadOrCreateStoreTransfer(cfg.Storage, req); stateErr != nil {
			failStore("persist resumable transfer state: "+stateErr.Error(), 1)
			return
		}
		if pregenCreds != nil {
			if stateErr := persistStoreTransferRegistration(cfg.Storage, req, *pregenCreds); stateErr != nil {
				failStore("persist transfer registration deadline: "+stateErr.Error(), 1)
				return
			}
		}
	}
	if admissionHandshake && existingStoredMeta == nil {
		storeCapacityMu.Lock()
		reservationErr := reserveStoreTransferCapacity(
			cfg.Storage, req, cfg.CapacityBytes, cfg.ZKBlockSize, admissionMarginBytes(cfg),
		)
		storeCapacityMu.Unlock()
		if reservationErr != nil {
			rejectStore(reservationErr.Error())
			return
		}
		// A durable reservation may be the one piece that crosses the close
		// threshold. Publish that transition before accepting its bytes so other
		// DOs stop creating obligations against this VK.
		maybeSyncAdmissionStatus(cfg)
	}
	partialPath := storeResumePath(cfg.Storage, req)
	hostReservationSettled := false
	// If any later stage fails, checkpoint what is really materialized. This
	// covers every return path, including ambiguous chain failures and lifecycle
	// rollback, without releasing a future-growth reservation prematurely.
	if cfg.CapacityBytes > 0 && pregenCreds != nil {
		defer func() {
			if hostReservationSettled {
				return
			}
			materialized := fileSizeIfExists(partialPath)
			if stored, ok := findStoredPieceByStoreReq(cfg.Storage, req); ok {
				if size := fileSizeIfExists(piecePath(cfg.Storage, stored.PieceRoot)); size > materialized {
					materialized = size
				}
			}
			if syncErr := syncHostFilesystemReservationMaterialized(cfg, req.TransferID, materialized); syncErr != nil {
				log.Printf("[filesystem-admission] preserve reservation failed transfer=%s: %v", req.TransferID, syncErr)
			}
		}()
	}
	// Activate only after every request, escrow, ACL, and durable local
	// admission check has succeeded. Malformed requests therefore cannot consume
	// an active on-chain transfer lease or leave resumable state behind.
	if pregenCreds != nil {
		capacityActivation, err = startQuoteActivationLease(cfg, req, *pregenCreds)
		if err != nil {
			failStoreForError("activate authoritative transfer capacity: ", err, 1)
			return
		}
		if capacityActivation != nil {
			defer capacityActivation.Stop()
		}
	}

	admissionPath := partialPath
	admissionSize := req.Size
	if existingStoredMeta != nil {
		admissionPath = ""
		admissionSize = 0
	}
	identity := transferIdentity(req.Uploader, requesterID)
	lease, retryAfter, admissionErr := transferController(cfg).acquire("upload", identity, admissionPath, admissionSize)
	if admissionErr != nil {
		writeJSON(s, StoreResp{
			OK: false, Busy: true, RetryAfterSeconds: retryAfter,
			TransferID: req.TransferID, Err: admissionErr.Error(),
		})
		return
	}
	defer lease.Release()

	var meta PieceMeta
	var done bool
	if existingStoredMeta != nil {
		meta = *existingStoredMeta
	} else if admissionHandshake {
		meta, done, err = receiveStorePieceV3(s, r, cfg, req)
	} else {
		meta, done, err = receiveStorePiece(s, r, cfg, req)
	}
	if done {
		return
	}
	if err != nil {
		failStore(err.Error(), requesterFailWeight(req.Size))
		return
	}
	commitmentHash, commitmentErr := computeCommitmentHash(meta.PieceRoot, commitmentNonce)
	if commitmentErr != nil {
		if existingStoredMeta == nil {
			_ = os.Remove(piecePath(cfg.Storage, meta.PieceRoot))
			_ = os.Remove(metaPath(cfg.Storage, meta.PieceRoot))
		}
		failStore("commitment hash computation failed: "+commitmentErr.Error(), 1)
		return
	}
	storeOperationLock, lockErr := acquireLifecycleOperationLock(cfg.Storage, "store", meta.PieceRoot)
	if lockErr != nil {
		if existingStoredMeta == nil {
			_ = os.Remove(piecePath(cfg.Storage, meta.PieceRoot))
			_ = os.Remove(metaPath(cfg.Storage, meta.PieceRoot))
		}
		failStore("acquire store lifecycle lock: "+lockErr.Error(), 1)
		return
	}
	defer storeOperationLock.Release()
	storeOperation := StoreLifecycleOperation{
		Version:                lifecycleJournalVersion,
		PieceRoot:              meta.PieceRoot,
		CommitmentHash:         commitmentHash,
		RegistrationCommitment: pregenRegistrationCommitment,
		Phase:                  "staged",
		CreatedAt:              nowRFC3339(),
	}
	if err := writeStoreLifecycleOperation(cfg.Storage, storeOperation); err != nil {
		if existingStoredMeta == nil {
			_ = os.Remove(piecePath(cfg.Storage, meta.PieceRoot))
			_ = os.Remove(metaPath(cfg.Storage, meta.PieceRoot))
		}
		failStore("persist store lifecycle: "+err.Error(), 1)
		return
	}
	capacityMutation, mutationErr := beginCapacityMutationOperation(
		cfg.Storage, storeCapacityMutationOperationID(commitmentHash, meta.PieceRoot), "store",
	)
	if mutationErr != nil {
		if existingStoredMeta == nil {
			_ = os.Remove(piecePath(cfg.Storage, meta.PieceRoot))
			_ = os.Remove(metaPath(cfg.Storage, meta.PieceRoot))
		}
		_ = removeStoreLifecycleOperation(cfg.Storage, storeOperation.PieceRoot)
		failStore("capacity publication coordination failed: "+mutationErr.Error(), 1)
		return
	}
	capacityMutationSettled := false
	defer func() {
		if !capacityMutationSettled {
			_ = capacityMutation.Abandon()
		}
		capacityMutation.Release()
	}()
	storeOperation.CapacityMutationSequence = capacityMutation.JournalSequence()
	if err := writeStoreLifecycleOperation(cfg.Storage, storeOperation); err != nil {
		_ = capacityMutation.Abandon()
		failStore("persist store capacity mutation: "+err.Error(), 1)
		return
	}
	// B.3: the byte-capacity admission decision is a short accounting read. It is taken under
	// the global accounting mutex and RELEASED immediately. Sector placement, capacity
	// publication and every chain RPC below then run without it, so uploads targeting different
	// partitions no longer serialise behind one another for their long-running work. The
	// durable outcome is verified again after the sector write, before any chain registration.
	if existingStoredMeta == nil {
		var capacityErr error
		storeCapacityMu.Lock()
		if !admissionHandshake {
			capacityErr = ensureAdmissionCapacityAvailableForUnreservedPiece(
				cfg.Storage, cfg.CapacityBytes, req.Size, cfg.ZKBlockSize, admissionMarginBytes(cfg),
			)
		} else {
			capacityErr = ensureCapacityAvailableForPiece(cfg.Storage, cfg.CapacityBytes, req.Size, cfg.ZKBlockSize)
		}
		storeCapacityMu.Unlock()
		if capacityErr != nil {
			// Piece bytes/meta were already staged by receiveStorePiece(); roll them back when
			// the capacity re-check rejects this store.
			_ = os.Remove(piecePath(cfg.Storage, meta.PieceRoot))
			_ = os.Remove(metaPath(cfg.Storage, meta.PieceRoot))
			rejectStore(capacityErr.Error())
			return
		}
	}
	log.Printf("[store] pieceRoot=%s", meta.PieceRoot)
	var partitionLease *partitionLifecycleLock
	var sectorReceipt SectorReceipt
	if existingStoredMeta != nil {
		sectorReceipt, partitionLease, err = storedSectorReceipt(cfg.Storage, meta, cfg)
	} else {
		sectorReceipt, meta, err = addPieceToSectorWithMutation(
			cfg.Storage, meta, cfg, capacityMutation, &partitionLease,
		)
	}
	if err != nil {
		log.Printf("[store ✗] sector failed: %v  pieceRoot=%s", err, meta.PieceRoot)
		storeOperation.LastError = err.Error()
		_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
		if _, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation); cleanupErr != nil {
			log.Printf("[lifecycle] sector failure cleanup pending piece=%s: %v", truncate(meta.PieceRoot, 18), cleanupErr)
		}
		failStore(err.Error(), requesterFailWeight(req.Size))
		return
	}
	defer partitionLease.Release()
	storeOperation.SectorID = sectorReceipt.SectorID
	storeOperation.Phase = "sector_committed"
	allSectorsForJournal, _ := listSectors(cfg.Storage)
	for _, sector := range allSectorsForJournal {
		if sector.SectorID == sectorReceipt.SectorID {
			storeOperation.DeadlineIndex = sector.DeadlineIndex
			storeOperation.PartitionIndex = sector.PartitionIndex
			break
		}
	}
	if err := writeStoreLifecycleOperation(cfg.Storage, storeOperation); err != nil {
		partitionLease.Release()
		if _, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation); cleanupErr != nil {
			log.Printf("[lifecycle] journal failure cleanup pending piece=%s: %v", truncate(meta.PieceRoot, 18), cleanupErr)
		}
		failStore("persist sector lifecycle: "+err.Error(), 1)
		return
	}
	if err := capacityMutation.Complete(); err != nil {
		storeOperation.LastError = err.Error()
		_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
		failStore("persist applied capacity mutation: "+err.Error(), 1)
		return
	}
	capacityMutationSettled = true
	// DEFECT F — LOCK ORDER. The partition-local write transition is complete and durable
	// (sector written, journal at sector_committed, capacity mutation applied), so the
	// partition lifecycle lock is released HERE, before the accounting re-check below.
	//
	// It must not be held across storeCapacityMu. The canonical order everywhere else in
	// this codebase is storeCapacityMu FIRST, then the partition lifecycle lock:
	//   lifecycle_reconcile.go:1412→1414 (deletion resume: mutex, then dl/pt lock)
	//   lifecycle_reconcile.go:1833/2132 → reconcileStoreLifecycleOperationLocked, whose
	//     documented contract is "storeCapacityMu must be held by the caller" and which
	//     takes the partition lock itself
	//   expired_gc.go:349→351
	// Taking storeCapacityMu while holding the partition lock inverted that order and
	// deadlocked the VK outright (proven live, smoke7 VK1 2026-08-14 20:27:05, pid 797259,
	// partition dl27-pt0): capacity mutation seq 11 "store" reached status=applied and its
	// goroutine blocked acquiring storeCapacityMu while holding dl27-pt0, while seq 12
	// "delete" sat at status=planned holding storeCapacityMu and blocking on dl27-pt0.
	// Neither ever released. Every later store and deletion, and the whole lifecycle
	// reconciler, blocked behind the mutex for 12 hours; only lock-free GETs still served.
	//
	// Nothing between here and the chain calls needs the partition lock: the accounting
	// re-check is a GLOBAL durable read guarded by storeCapacityMu, not by this partition,
	// and the rollback path already released the lease before reconciling. Releasing
	// earlier only shortens the hold window, which is what B.3 wants. Release is
	// idempotent, so the deferred release above and the failure-path releases stay correct.
	partitionLease.Release()
	// B.3: the byte-admission decision above did not hold a lock across the sector write, so
	// verify the DURABLE outcome now — before any chain registration. A store that lost a
	// concurrent admission race is failed here and rolled back by the existing lifecycle
	// cleanup, so a race can never leave over-admitted capacity registered on-chain.
	if existingStoredMeta == nil && cfg.CapacityBytes > 0 {
		storeCapacityMu.Lock()
		accounting, accountingErr := computeCapacityAccounting(cfg.Storage, cfg.CapacityBytes)
		storeCapacityMu.Unlock()
		if accountingErr == nil && !accounting.OK {
			storeOperation.LastError = accounting.Error
			_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
			partitionLease.Release()
			if _, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation); cleanupErr != nil {
				log.Printf("[lifecycle] capacity verification cleanup pending piece=%s: %v",
					truncate(meta.PieceRoot, 18), cleanupErr)
			}
			rejectStore("declared capacity exceeded after sector placement: " + accounting.Error)
			return
		}
	}
	if cfg.CapacityBytes > 0 {
		log.Printf("[capacity] free-space update queued for proof daemon  pieceRoot=%s", meta.PieceRoot)
	}
	// B.3: registration is unbounded external work and must run outside all three upload-path
	// locks so it cannot block another partition's uploads. The partition lifecycle lock was
	// already released above (see DEFECT F), before the accounting re-check; this repeat is
	// kept only because Release is idempotent and the invariant "no partition lock crosses a
	// chain RPC" is asserted at this exact boundary.
	partitionLease.Release()
	if cfg.FileRegistrationContract != "" && cfg.ChainProofCmd != "" {
		if _, err := registerCurrentDataPartitionForSector(cfg, sectorReceipt.SectorID); errors.Is(
			err, errPartitionRegistrationDeferred) {
			// Not a failure. The bytes are durably committed and the deletion that
			// owns this partition will register the successor including this sector.
			// The store stays at sector_committed for the reconciler to observe.
			storeOperation.LastError = ""
			if writeErr := writeStoreLifecycleOperation(cfg.Storage, storeOperation); writeErr != nil {
				log.Printf("[lifecycle] deferred-registration journal warning piece=%s: %v",
					truncate(meta.PieceRoot, 18), writeErr)
			}
		} else if err != nil {
			log.Printf("[store ✗] partition registration failed: %v  pieceRoot=%s", err, meta.PieceRoot)
			storeOperation.LastError = err.Error()
			_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
			partitionLease.Release()
			if _, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation); cleanupErr != nil {
				log.Printf("[lifecycle] partition failure cleanup pending piece=%s: %v", truncate(meta.PieceRoot, 18), cleanupErr)
			}
			failStore("partition registration failed: "+err.Error(), requesterFailWeight(req.Size))
			return
		} else {
			storeOperation.Phase = "partition_registered"
			storeOperation.LastError = ""
			if err := writeStoreLifecycleOperation(cfg.Storage, storeOperation); err != nil {
				log.Printf("[lifecycle] partition journal update warning piece=%s: %v", truncate(meta.PieceRoot, 18), err)
			}
		}
	}

	resp := StoreResp{
		OK:               true,
		Name:             meta.Name,
		Size:             meta.Size,
		PieceRoot:        meta.PieceRoot,
		PieceID:          meta.PieceRoot,
		CID:              meta.CID,
		PieceHash:        meta.PieceHash,
		HashAlg:          HashAlgSha256,
		RootAlg:          RootAlgMerkleSHA256,
		PieceBlockSize:   meta.PieceBlockSize,
		PieceBlockCount:  meta.PieceBlockCount,
		SectorID:         sectorReceipt.SectorID,
		SectorRoot:       sectorReceipt.SectorRoot,
		SectorExpiration: sectorReceipt.SectorExpiration,
		PiecePosition:    sectorReceipt.PiecePosition,
		InclusionProof:   sectorReceipt.InclusionProof,
		StoredAt:         meta.StoredAt,
		FileFormat:       meta.FileFormat,
	}

	// ── Mandatory on-chain file registration ──────────────────────────────────
	// When FileRegistrationContract is configured, registration MUST succeed
	// before a receipt is issued. A store that cannot establish a public on-chain
	// anchor is considered failed — VK returns an error to DO.
	//
	// Exception: ErrAlreadyRegistered means the record exists from a previous
	// attempt by this VK; treat as success (idempotent, no new txHash).
	registrationTxHash := ""
	if cfg.FileRegistrationContract != "" && commitmentHash != "" {
		allSectorsForReg, _ := listSectors(cfg.Storage)
		var sectorForReg SectorMeta
		for _, ss := range allSectorsForReg {
			if ss.SectorID == sectorReceipt.SectorID {
				sectorForReg = ss
				break
			}
		}
		dl, pt := 0, 0
		if sectorForReg.SectorID != "" {
			var pRoot string
			dl, pt, pRoot, err = currentPartitionForSector(sectorForReg, allSectorsForReg, cfg)
			if err != nil {
				storeOperation.LastError = err.Error()
				_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
				partitionLease.Release()
				if _, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation); cleanupErr != nil {
					log.Printf("[lifecycle] partition lookup cleanup pending piece=%s: %v", truncate(meta.PieceRoot, 18), cleanupErr)
				}
				failStore("partition lookup failed: "+err.Error(), 1)
				return
			}
			_ = pRoot
		}
		serviceEnd := meta.ServiceEnd
		if serviceEnd <= 0 {
			serviceEnd = sectorReceipt.SectorExpiration
		}

		// Read ZKPieceCommitment from the sector that was just updated.
		zkPCForReg := ""
		if sectorForReg.ZKPieceCommitment != "" {
			zkPCForReg = sectorForReg.ZKPieceCommitment
		} else {
			// Fallback: compute on the fly if sector was not yet reloaded.
			if computed, cErr := computeZKPieceCommitment(sectorForReg.PieceRoots); cErr == nil {
				zkPCForReg = computed
			}
		}
		var txHash string
		var regErr error
		// Proof/partition preparation may be expensive. Re-read the blockchain
		// deadline immediately before registration so a VK never knowingly creates
		// a late record after accepting bytes.
		if pregenCreds != nil {
			_, regErr = verifyEscrowDeposit(cfg, *pregenCreds)
		}
		if regErr == nil {
			txHash, regErr = registerFileStorageOnChain(
				cfg,
				commitmentHash,
				sectorReceipt.SectorRoot,
				zkPCForReg,
				dl,
				pt,
				serviceEnd,
				pregenRegistrationCommitment,
				deletionAuthHash,
			)
		}
		if regErr != nil && !errors.Is(regErr, ErrAlreadyRegistered) {
			storeOperation.LastError = regErr.Error()
			_ = writeStoreLifecycleOperation(cfg.Storage, storeOperation)
			partitionLease.Release()
			registered, cleanupErr := reconcileStoreLifecycleUnderAccountingLock(cfg, storeOperation)
			if !registered {
				if cleanupErr != nil {
					log.Printf("[lifecycle] file registration cleanup pending piece=%s: %v", truncate(meta.PieceRoot, 18), cleanupErr)
				}
				failStoreForError("file registration failed: ", regErr, requesterFailWeight(req.Size))
				return
			}
			log.Printf("[file_reg] recovered accepted registration after client error piece=%s", truncate(meta.PieceRoot, 18))
		}
		registrationTxHash = txHash // empty string when ErrAlreadyRegistered
		storeOperation.Phase = "file_registered"
		storeOperation.LastError = ""
	}
	if err := removeStoreLifecycleOperation(cfg.Storage, storeOperation.PieceRoot); err != nil {
		log.Printf("[lifecycle] completed store journal cleanup warning piece=%s: %v", truncate(meta.PieceRoot, 18), err)
	}

	// ── Payment commitment (VKEscrow) ────────────────────────────────────────
	// When a quote was pre-issued (pregenCreds != nil), use those credentials —
	// they were already saved and verified. Otherwise generate fresh ones now.
	paymentCommitment := ""
	sizeCommitment := ""
	sizeNonce := ""
	agreedPriceWei := ""
	registrationCommitmentForReceipt := pregenRegistrationCommitment
	linkCommitmentForReceipt := ""

	if commitmentHash != "" {
		if pregenCreds != nil {
			// Quote-linked flow: update the saved credentials with the now-known commitmentHash.
			paymentCommitment = pregenCreds.PaymentCommitment
			sizeCommitment = pregenCreds.SizeCommitment
			sizeNonce = pregenCreds.SizeNonce
			agreedPriceWei = pregenCreds.AgreedPriceWei
			linkCommitmentForReceipt = pregenCreds.LinkCommitment
			updatedCreds := *pregenCreds
			updatedCreds.CommitmentHash = commitmentHash
			updatedCreds.PieceRoot = meta.PieceRoot
			updatedCreds.DeletionAuthHash = deletionAuthHash
			if saveErr := SavePaymentCredentials(cfg.Storage, updatedCreds); saveErr != nil {
				log.Printf("[payment] update credentials error: %v", saveErr)
			} else {
				log.Printf("[payment] credentials linked to commitmentHash=%s  pc=%s",
					truncate(commitmentHash, 18), truncate(paymentCommitment, 18))
			}
		} else {
			// Standard flow: generate all secrets now.
			nullifier, secret, pc, pcErr := GeneratePaymentCommitment()
			if pcErr != nil {
				log.Printf("[payment] GeneratePaymentCommitment error: %v", pcErr)
			} else {
				regNull, regSec, regCommitment, rnErr := GenerateRegistrationCommitment()
				if rnErr != nil {
					log.Printf("[payment] GenerateRegistrationCommitment error: %v", rnErr)
				} else {
					sn, sc, scErr := GenerateSizeCommitment(meta.Size)
					if scErr != nil {
						log.Printf("[payment] GenerateSizeCommitment error: %v", scErr)
					} else {
						ln, lc, lcErr := GenerateLinkCommitment(pc, regCommitment)
						if lcErr != nil {
							log.Printf("[payment] GenerateLinkCommitment error: %v", lcErr)
						} else {
							paymentCommitment = pc
							sizeCommitment = sc
							sizeNonce = sn
							registrationCommitmentForReceipt = regCommitment
							linkCommitmentForReceipt = lc

							serviceEnd := meta.ServiceEnd
							if serviceEnd <= 0 {
								serviceEnd = sectorReceipt.SectorExpiration
							}
							if cfg.StorageFee > 0 && cfg.SuToWeiRate > 0 && serviceEnd > 0 {
								now := time.Now().UTC().Unix()
								durationSec := serviceEnd - now
								if durationSec < 0 {
									durationSec = 0
								}
								const secsPerDay = int64(86400)
								durationDays := (durationSec + secsPerDay - 1) / secsPerDay
								price := storagePriceWeiForBytes(cfg.StorageFee, meta.Size, durationDays, cfg.SuToWeiRate)
								agreedPriceWei = price.String()
							}

							creds := PaymentCredentials{
								CommitmentHash:         commitmentHash,
								CommitmentNonce:        commitmentNonce,
								PieceRoot:              meta.PieceRoot,
								PaymentCommitment:      paymentCommitment,
								Nullifier:              nullifier,
								Secret:                 secret,
								SizeCommitment:         sizeCommitment,
								SizeNonce:              sizeNonce,
								PieceSize:              meta.Size,
								ServiceEnd:             serviceEnd,
								AgreedPriceWei:         agreedPriceWei,
								RegNullifier:           regNull,
								RegSecret:              regSec,
								RegistrationCommitment: regCommitment,
								LinkNonce:              ln,
								LinkCommitment:         lc,
								DeletionAuthHash:       deletionAuthHash,
							}
							if saveErr := SavePaymentCredentials(cfg.Storage, creds); saveErr != nil {
								log.Printf("[payment] save credentials error: %v", saveErr)
							} else {
								log.Printf("[payment] credentials saved  commitmentHash=%s  pc=%s",
									truncate(commitmentHash, 18), truncate(paymentCommitment, 18))
							}
						}
					}
				}
			}
		}
	}
	// ── Sign and attach a private receipt when VK signing key is configured ───
	if cfg.VKPrivKeyHex != "" && cfg.VKAddress != "" {
		privKey, keyErr := ParseVKPrivKey(cfg.VKPrivKeyHex)
		if keyErr != nil {
			log.Printf("[receipt] private key parse error: %v", keyErr)
		} else {
			allSectors, _ := listSectors(cfg.Storage)
			var sector SectorMeta
			for _, ss := range allSectors {
				if ss.SectorID == sectorReceipt.SectorID {
					sector = ss
					break
				}
			}
			if sector.SectorID == "" {
				log.Printf("[receipt] sector %s not found in sector list; skipping receipt", sectorReceipt.SectorID)
			} else {
				pr, receiptErr := buildPrivateReceipt(
					cfg.Storage, privKey, cfg.VKAddress,
					cfg.ChainID, cfg.StorageProofContract,
					meta, sector, allSectors, cfg,
					commitmentHash, commitmentNonce, registrationTxHash,
					paymentCommitment, sizeCommitment, sizeNonce, agreedPriceWei,
					registrationCommitmentForReceipt, linkCommitmentForReceipt,
					deletionAuthHash,
				)
				if receiptErr != nil {
					log.Printf("[receipt] build error: %v", receiptErr)
				} else {
					saveIssuedReceipt(cfg.Storage, pr)
					resp.PrivateReceipt = &pr
				}
			}
		}
	}

	log.Printf("[store ✓] pieceRoot=%s sectorId=%s pos=%d tx=%s", meta.PieceRoot, sectorReceipt.SectorID, sectorReceipt.PiecePosition, registrationTxHash)
	if admissionHandshake {
		if req.PaymentCommitment != "" {
			if err := markQuoteReservationStored(cfg.Storage, req.TransferID, req.PaymentCommitment); err != nil {
				log.Printf("[quote-reservation] registered store awaiting local reconciliation transfer=%s: %v", req.TransferID, err)
				writeJSON(s, StoreResp{
					OK: false, TransferID: req.TransferID,
					Err: "store registered but durable capacity conversion could not be persisted; retry safely with the same transferId",
				})
				return
			}
			hostReservationSettled = true
		}
		resp.TransferID = req.TransferID
		resp.Complete = true
		if err := completeStoreTransfer(cfg.Storage, req, resp); err != nil {
			log.Printf("[transfer] CRITICAL completed response persistence failed transfer=%s: %v", req.TransferID, err)
			writeJSON(s, StoreResp{
				OK: false, TransferID: req.TransferID,
				Err: "store completed but durable transfer receipt could not be persisted; retry safely with the same transferId",
			})
			return
		}
	}
	markRequesterSuccess(requesterID, time.Now().UTC())
	maybeSyncAdmissionStatus(cfg)
	linkStoredPartitionBeforeResponse(cfg, commitmentHash)
	writeJSON(s, resp)
}

// linkStoredPartitionBeforeResponse sends verifyPartitionContainsSector() for a
// just-stored piece, before the store response goes back to the data owner.
//
// The DO checks partitionLinked the instant this response returns. Leaving the
// call to the reconciler's 60-second sweep meant that check almost always ran
// first: every fresh upload came back "waiting for VK to link the sector to its
// partition", which the DO correctly reports as pending and retries. Measured on
// a live 10-VK run, pieces stayed unlinked for 10s to 2.5min each.
//
// The VK remains the sender. That is the entire point of the privacy fix — the
// DO's own signed call named the VK on chain from upload time and defeated the
// commitment scheme. Only the timing moves here; who sends it does not, so the
// DO↔VK relationship stays hidden exactly as before.
//
// This runs after every durable write, so a failure is never a store failure:
// the piece is stored, registered, and its partition is already registered on
// chain. On any error the reconciler sweep stays the safety net and retries.
func linkStoredPartitionBeforeResponse(cfg ServerConfig, commitmentHash string) {
	if strings.TrimSpace(commitmentHash) == "" || cfg.FileRegistrationContract == "" {
		return
	}
	txHash, err := linkPartitionOnChain(cfg, commitmentHash)
	if err != nil {
		log.Printf("[partition_link] not linkable at store, reconciler will retry  commitmentHash=%s: %v",
			truncate(commitmentHash, 18), err)
		return
	}
	if txHash != "" {
		log.Printf("[partition_link] linked at store  commitmentHash=%s  tx=%s",
			truncate(commitmentHash, 18), txHash)
	}
}

func storedSectorReceipt(storage string, meta PieceMeta, cfg ServerConfig) (SectorReceipt, *partitionLifecycleLock, error) {
	sectors, err := listSectors(storage)
	if err != nil {
		return SectorReceipt{}, nil, err
	}
	for _, sector := range sectors {
		if sector.SectorID != meta.SectorID {
			continue
		}
		position := -1
		for idx, root := range sector.PieceRoots {
			if sameRoot(root, meta.PieceRoot) {
				position = idx
				break
			}
		}
		if position < 0 || !sameRoot(sector.SectorRoot, meta.SectorRoot) {
			return SectorReceipt{}, nil, fmt.Errorf("stored piece metadata no longer matches immutable sector")
		}
		var lease *partitionLifecycleLock
		if cfg.FileRegistrationContract != "" && validAssignedPartition(sector, PartitionKindData, cfg.DeadlineCount) {
			lease, err = acquirePartitionLifecycleLock(storage, sector.DeadlineIndex, sector.PartitionIndex)
			if err != nil {
				return SectorReceipt{}, nil, err
			}
		}
		proof, err := computeSectorProof(sector.PieceRoots, position)
		if err != nil {
			lease.Release()
			return SectorReceipt{}, nil, err
		}
		return SectorReceipt{
			SectorID: sector.SectorID, SectorRoot: sector.SectorRoot,
			SectorExpiration: sector.Expiration, PiecePosition: position,
			InclusionProof: proof,
		}, lease, nil
	}
	return SectorReceipt{}, nil, fmt.Errorf("stored sector %s not found", meta.SectorID)
}

func handleGet(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	r := bufio.NewReader(s)
	var req GetReq
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		writeJSON(s, GetResp{OK: false, Err: err.Error()})
		return
	}
	pieceRoot := requestPieceRoot(req)
	if pieceRoot == "" {
		writeJSON(s, GetResp{OK: false, Err: "missing pieceRoot"})
		return
	}
	if err := validateRoot(pieceRoot); err != nil {
		writeJSON(s, GetResp{OK: false, Err: "invalid pieceRoot"})
		return
	}
	log.Printf("[get ←] pieceRoot=%s requester=%s", pieceRoot, req.Requester)
	if pending, pendingErr := pieceDeletionPending(cfg.Storage, pieceRoot); pendingErr != nil {
		writeJSON(s, GetResp{OK: false, Err: "piece deletion state unavailable"})
		return
	} else if pending {
		log.Printf("[get ✗] pieceRoot=%s deletion pending", pieceRoot)
		writeJSON(s, GetResp{OK: false, Err: "piece deletion pending"})
		return
	}
	// Fail closed. This used to run the check only when an RPC URL and an ACL
	// address happened to be configured, so a node started without them served
	// every piece it held to anyone who asked -- and announced it in one line of
	// startup output that nobody outside the machine can see. A missing flag is
	// not consent. Reads stop unless access control is configured or the
	// operator has explicitly asked for an open node.
	if accessControlConfigured(cfg) {
		if err := authorizeGetRequest(cfg.RPCURL, cfg.ACLAddress, cfg.Storage, req); err != nil {
			log.Printf("[get ✗] pieceRoot=%s access denied: %v", pieceRoot, err)
			writeJSON(s, GetResp{OK: false, Err: "access denied: " + err.Error()})
			return
		}
	} else if !cfg.AllowUnauthenticatedReads {
		log.Printf("[get ✗] pieceRoot=%s refused: access control is not configured", pieceRoot)
		writeJSON(s, GetResp{OK: false, Err: "access control is not configured on this vault keeper"})
		return
	}
	identity := transferIdentity(req.Requester, requesterIDFromStream(s))
	lease, retryAfter, admissionErr := transferController(cfg).acquire("download", identity, "", 0)
	if admissionErr != nil {
		writeJSON(s, GetResp{OK: false, Busy: true, RetryAfterSeconds: retryAfter, Err: admissionErr.Error()})
		return
	}
	defer lease.Release()
	ok, got, err := verifyStoredPiece(cfg.Storage, pieceRoot)
	if err != nil || !ok {
		if got == "" {
			log.Printf("[get ✗] pieceRoot=%s not found", pieceRoot)
			writeJSON(s, GetResp{OK: false, Err: "piece not found"})
		} else {
			log.Printf("[get ✗] pieceRoot=%s integrity check failed", pieceRoot)
			writeJSON(s, GetResp{OK: false, Err: "stored piece failed integrity check"})
		}
		return
	}
	path := piecePath(cfg.Storage, pieceRoot)
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[get ✗] pieceRoot=%s open failed: %v", pieceRoot, err)
		writeJSON(s, GetResp{OK: false, Err: "piece not found"})
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	if req.Offset < 0 || req.Offset > st.Size() {
		writeJSON(s, GetResp{OK: false, Err: fmt.Sprintf("bad offset %d for size %d", req.Offset, st.Size())})
		return
	}
	if req.Offset > 0 {
		if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
			writeJSON(s, GetResp{OK: false, Err: err.Error()})
			return
		}
	}
	log.Printf("[get ✓] pieceRoot=%s size=%d requester=%s", pieceRoot, st.Size(), req.Requester)
	pieceFormat := ""
	if m, merr := readMeta(cfg.Storage, pieceRoot); merr == nil {
		pieceFormat = m.FileFormat
	}
	writeJSON(s, GetResp{OK: true, Size: st.Size() - req.Offset, TotalSize: st.Size(), Offset: req.Offset, PieceRoot: normalizeRoot(pieceRoot), RootAlg: RootAlgMerkleSHA256, PieceBlockSize: metaOrDefaultPieceBlockSize(cfg.Storage, pieceRoot, cfg.PieceBlockSize), FileFormat: pieceFormat})
	_, _ = io.Copy(s, f)
}

func validateExpectedPieceCommitmentParameters(req StoreReq, configuredBlockSize int64) error {
	if strings.TrimSpace(req.ExpectedPieceRoot) == "" {
		return nil
	}
	if configuredBlockSize <= 0 {
		return fmt.Errorf("VK protocol piece block size is not configured")
	}
	if req.ExpectedPieceBlockSize <= 0 || req.ExpectedPieceBlockSize != configuredBlockSize {
		return fmt.Errorf(
			"expected piece block size %d does not match VK protocol block size %d",
			req.ExpectedPieceBlockSize, configuredBlockSize,
		)
	}
	return nil
}

func validateExpectedPieceCommitment(path string, req StoreReq, configuredBlockSize int64) error {
	if err := validateExpectedPieceCommitmentParameters(req, configuredBlockSize); err != nil {
		return err
	}
	if strings.TrimSpace(req.ExpectedPieceRoot) == "" {
		// Only the isolated legacy /store/2 protocol can reach this case. Every
		// authenticated /store/3 request is rejected earlier by authorization.
		return nil
	}
	computed, _, _, size, err := computePieceCommitment(path, configuredBlockSize)
	if err != nil {
		return fmt.Errorf("compute expected piece commitment: %w", err)
	}
	if size != req.Size {
		return fmt.Errorf("expected piece size %d but received %d", req.Size, size)
	}
	if !strings.EqualFold(normalizeRoot(computed), normalizeRoot(req.ExpectedPieceRoot)) {
		return fmt.Errorf("received bytes do not match DO-signed expectedPieceRoot")
	}
	return nil
}

func receiveStorePiece(s network.Stream, r *bufio.Reader, cfg ServerConfig, req StoreReq) (PieceMeta, bool, error) {
	// B.1: network transfer must never run under the short allocator lock.
	noteLockConfinedWork("store-piece-transfer")
	if req.Resume {
		if meta, ok := findStoredPieceByStoreReq(cfg.Storage, req); ok {
			writeJSON(s, StoreResp{
				OK:              true,
				Complete:        true,
				ResumeOffset:    meta.Size,
				Name:            meta.Name,
				Size:            meta.Size,
				PieceRoot:       meta.PieceRoot,
				PieceID:         meta.PieceID,
				CID:             meta.CID,
				PieceHash:       meta.PieceHash,
				HashAlg:         meta.HashAlg,
				RootAlg:         meta.RootAlg,
				PieceBlockSize:  meta.PieceBlockSize,
				PieceBlockCount: meta.PieceBlockCount,
				SectorID:        meta.SectorID,
				SectorRoot:      meta.SectorRoot,
				PiecePosition:   meta.PiecePosition,
				StoredAt:        meta.StoredAt,
				FileFormat:      meta.FileFormat,
			})
			return PieceMeta{}, true, nil
		}

		partialPath := storeResumePath(cfg.Storage, req)
		offset := fileSizeIfExists(partialPath)
		if req.Probe {
			writeJSON(s, StoreResp{OK: true, ResumeOffset: offset, Complete: false, Size: req.Size})
			return PieceMeta{}, true, nil
		}
		if req.Offset < 0 || req.Offset > req.Size {
			writeJSON(s, StoreResp{OK: false, Err: "invalid resume offset", ResumeOffset: offset})
			return PieceMeta{}, true, nil
		}
		if req.Offset != offset {
			writeJSON(s, StoreResp{OK: false, Err: "resume offset mismatch", ResumeOffset: offset})
			return PieceMeta{}, true, nil
		}
		if err := os.MkdirAll(filepath.Dir(partialPath), 0700); err != nil {
			return PieceMeta{}, false, err
		}
		flags := os.O_CREATE | os.O_WRONLY
		if req.Offset == 0 {
			flags |= os.O_TRUNC
		}
		tmp, err := os.OpenFile(partialPath, flags, 0600)
		if err != nil {
			return PieceMeta{}, false, err
		}
		if _, err := tmp.Seek(req.Offset, io.SeekStart); err != nil {
			tmp.Close()
			return PieceMeta{}, false, err
		}
		remaining := req.Size - req.Offset
		n, err := io.CopyN(tmp, r, remaining)
		if err != nil {
			tmp.Close()
			writeJSON(s, StoreResp{OK: false, Err: "transfer interrupted: " + err.Error(), ResumeOffset: req.Offset + n})
			return PieceMeta{}, true, nil
		}
		if n != remaining {
			tmp.Close()
			writeJSON(s, StoreResp{OK: false, Err: "received size does not match remaining request size", ResumeOffset: req.Offset + n})
			return PieceMeta{}, true, nil
		}
		if err := tmp.Close(); err != nil {
			return PieceMeta{}, false, err
		}
		if err := validateRIDAPieceFile(partialPath, req); err != nil {
			_ = os.Remove(partialPath)
			writeJSON(s, StoreResp{OK: false, Err: "invalid RIDA piece: " + err.Error(), ResumeOffset: 0})
			return PieceMeta{}, true, nil
		}
		if err := validateExpectedPieceCommitment(partialPath, req, cfg.PieceBlockSize); err != nil {
			_ = os.Remove(partialPath)
			_ = syncHostFilesystemReservationMaterialized(cfg, req.TransferID, 0)
			writeJSON(s, StoreResp{OK: false, Err: err.Error(), ResumeOffset: 0})
			return PieceMeta{}, true, nil
		}
		meta, err := storePieceFromTemp(cfg.Storage, partialPath, req, cfg.PieceBlockSize)
		if err != nil {
			return PieceMeta{}, false, err
		}
		return meta, false, nil
	}

	tmp, err := os.CreateTemp(tmpDir(cfg.Storage), "incoming-*")
	if err != nil {
		return PieceMeta{}, false, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	n, err := io.CopyN(tmp, r, req.Size)
	if err != nil {
		tmp.Close()
		return PieceMeta{}, false, err
	}
	if n != req.Size {
		tmp.Close()
		return PieceMeta{}, false, fmt.Errorf("received size does not match request size")
	}
	if err := tmp.Close(); err != nil {
		return PieceMeta{}, false, err
	}
	if err := validateRIDAPieceFile(tmpName, req); err != nil {
		return PieceMeta{}, false, fmt.Errorf("invalid RIDA piece: %w", err)
	}
	if err := validateExpectedPieceCommitment(tmpName, req, cfg.PieceBlockSize); err != nil {
		return PieceMeta{}, false, err
	}

	meta, err := storePieceFromTemp(cfg.Storage, tmpName, req, cfg.PieceBlockSize)
	if err != nil {
		log.Printf("[store ✗] store failed: %v", err)
		return PieceMeta{}, false, err
	}
	return meta, false, nil
}

// receiveStorePieceV3 performs admission before accepting bytes and makes the
// VK's durable partial-file offset authoritative for every resume attempt.
func receiveStorePieceV3(s network.Stream, r *bufio.Reader, cfg ServerConfig, req StoreReq) (PieceMeta, bool, error) {
	// B.1: network transfer must never run under the short allocator lock.
	noteLockConfinedWork("store-piece-transfer-v3")
	partialPath := storeResumePath(cfg.Storage, req)
	offset := fileSizeIfExists(partialPath)
	if offset < 0 || offset > req.Size {
		_ = os.Remove(partialPath)
		_ = syncHostFilesystemReservationMaterialized(cfg, req.TransferID, 0)
		writeJSON(s, StoreResp{OK: false, TransferID: req.TransferID, Err: "invalid persisted partial upload", ResumeOffset: 0})
		return PieceMeta{}, true, nil
	}
	if err := os.MkdirAll(filepath.Dir(partialPath), 0700); err != nil {
		return PieceMeta{}, false, err
	}
	if err := syncHostFilesystemReservationMaterialized(cfg, req.TransferID, offset); err != nil {
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: "physical filesystem admission failed: " + err.Error(), ResumeOffset: offset,
		})
		return PieceMeta{}, true, nil
	}
	writeJSON(s, StoreResp{
		OK: true, Ready: true, TransferID: req.TransferID,
		ResumeOffset: offset, Complete: false, Size: req.Size,
	})

	flags := os.O_CREATE | os.O_WRONLY
	if offset == 0 {
		flags |= os.O_TRUNC
	}
	tmp, err := os.OpenFile(partialPath, flags, 0600)
	if err != nil {
		return PieceMeta{}, false, err
	}
	if _, err := tmp.Seek(offset, io.SeekStart); err != nil {
		tmp.Close()
		return PieceMeta{}, false, err
	}
	remaining := req.Size - offset
	n, copyErr := copyNWithHostFilesystemReservation(cfg, req.TransferID, tmp, r, offset, remaining)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if syncErr != nil {
		_ = os.Remove(partialPath)
		_ = syncHostFilesystemReservationMaterialized(cfg, req.TransferID, 0)
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: "partial upload durability failed: " + syncErr.Error(), ResumeOffset: 0,
		})
		return PieceMeta{}, true, nil
	}
	if copyErr != nil {
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: "transfer interrupted: " + copyErr.Error(), ResumeOffset: offset + n,
		})
		return PieceMeta{}, true, nil
	}
	if n != remaining {
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: "received size does not match remaining request size", ResumeOffset: offset + n,
		})
		return PieceMeta{}, true, nil
	}
	if closeErr != nil {
		return PieceMeta{}, false, closeErr
	}
	if err := validateRIDAPieceFile(partialPath, req); err != nil {
		_ = os.Remove(partialPath)
		_ = syncHostFilesystemReservationMaterialized(cfg, req.TransferID, 0)
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: "invalid RIDA piece: " + err.Error(), ResumeOffset: 0,
		})
		return PieceMeta{}, true, nil
	}
	if err := validateExpectedPieceCommitment(partialPath, req, cfg.PieceBlockSize); err != nil {
		_ = os.Remove(partialPath)
		_ = syncHostFilesystemReservationMaterialized(cfg, req.TransferID, 0)
		writeJSON(s, StoreResp{
			OK: false, TransferID: req.TransferID,
			Err: err.Error(), ResumeOffset: 0,
		})
		return PieceMeta{}, true, nil
	}
	meta, err := storePieceFromTemp(cfg.Storage, partialPath, req, cfg.PieceBlockSize)
	if err != nil {
		return PieceMeta{}, false, err
	}
	return meta, false, nil
}

func storeResumePath(storage string, req StoreReq) string {
	if validTransferID(req.TransferID) {
		return transferPartialPath(storage, req.TransferID)
	}
	key := fmt.Sprintf("%s|%d|%s|%d", normalizeFileID(req.FileID), req.PieceIndex, req.Name, req.Size)
	sum := ethcrypto.Keccak256Hash([]byte(key)).Hex()
	return filepath.Join(tmpDir(storage), "resume-"+safeID(sum)+".part")
}

func fileSizeIfExists(path string) int64 {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return 0
	}
	return st.Size()
}

func findStoredPieceByStoreReq(storage string, req StoreReq) (PieceMeta, bool) {
	entries, err := os.ReadDir(metaDir(storage))
	if err != nil {
		return PieceMeta{}, false
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var meta PieceMeta
		data, err := os.ReadFile(filepath.Join(metaDir(storage), entry.Name()))
		if err != nil || json.Unmarshal(data, &meta) != nil {
			continue
		}
		matches := false
		if validTransferID(req.TransferID) {
			matches = meta.TransferID == req.TransferID
		} else {
			matches = sameFileID(meta.FileID, req.FileID) &&
				meta.PieceIndex == req.PieceIndex &&
				meta.Name == req.Name && meta.Size == req.Size
		}
		if matches && strings.TrimSpace(req.ExpectedPieceRoot) != "" &&
			!strings.EqualFold(meta.PieceRoot, normalizeRoot(req.ExpectedPieceRoot)) {
			continue
		}
		if matches {
			return meta, true
		}
	}
	return PieceMeta{}, false
}

func handleProve(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	r := bufio.NewReader(s)
	var req ProveReq
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		writeJSON(s, ProveResp{OK: false, Err: err.Error()})
		return
	}
	pieceRoot := requestProveRoot(req)
	if pieceRoot == "" {
		writeJSON(s, ProveResp{OK: false, Err: "missing pieceRoot"})
		return
	}
	if err := validateRoot(pieceRoot); err != nil {
		writeJSON(s, ProveResp{OK: false, Err: "invalid pieceRoot"})
		return
	}
	log.Printf("[prove ←] pieceRoot=%s", pieceRoot)

	// Answering this means re-reading the whole stored piece and recomputing its
	// commitment. The request that asks for it is a few dozen bytes and needs no
	// credentials, so without a bound one stranger can hold the keeper's disk and
	// CPU with a stream of them -- the cheapest useful attack on a storage node
	// is not theft, it is work. Proofs stay public; what they cost is bounded,
	// by the same controller that already bounds uploads and downloads.
	proveLease, proveRetryAfter, proveAdmissionErr := transferController(cfg).acquire(
		"download", transferIdentity("", requesterIDFromStream(s)), "", 0)
	if proveAdmissionErr != nil {
		writeJSON(s, ProveResp{OK: false, Busy: true,
			RetryAfterSeconds: proveRetryAfter, Err: proveAdmissionErr.Error()})
		return
	}
	defer proveLease.Release()

	meta, err := readMeta(cfg.Storage, pieceRoot)
	if err != nil {
		log.Printf("[prove] pieceRoot=%s exists=false", pieceRoot)
		writeJSON(s, ProveResp{OK: true, Exists: false, PieceRoot: normalizeRoot(pieceRoot), PieceID: normalizeRoot(pieceRoot)})
		return
	}
	ok, got, err := verifyStoredPiece(cfg.Storage, pieceRoot)
	if err != nil || !ok {
		log.Printf("[prove ✗] pieceRoot=%s integrity failed: %s", pieceRoot, got)
		writeJSON(s, ProveResp{OK: false, Exists: false, PieceRoot: normalizeRoot(pieceRoot), Err: fmt.Sprintf("integrity failed: got %s", got)})
		return
	}
	log.Printf("[prove ✓] pieceRoot=%s exists=true size=%d sectorId=%s", pieceRoot, meta.Size, meta.SectorID)
	writeJSON(s, ProveResp{OK: true, Exists: true, PieceRoot: meta.PieceRoot, PieceID: meta.PieceRoot, PieceHash: meta.PieceHash, HashAlg: meta.HashAlg, RootAlg: meta.RootAlg, PieceBlockSize: meta.PieceBlockSize, PieceBlockCount: meta.PieceBlockCount, Size: meta.Size, SectorID: meta.SectorID, SectorRoot: meta.SectorRoot, PiecePosition: meta.PiecePosition})
}

func requestPieceRoot(req GetReq) string {
	for _, v := range []string{req.PieceRoot, req.PieceID, req.CID} {
		if stringsTrim(v) != "" {
			return normalizeRoot(v)
		}
	}
	return ""
}

func requestProveRoot(req ProveReq) string {
	for _, v := range []string{req.PieceRoot, req.PieceID, req.CID} {
		if stringsTrim(v) != "" {
			return normalizeRoot(v)
		}
	}
	return ""
}

func stringsTrim(s string) string { return strings.TrimSpace(s) }

func listSectorsJSON(storage string) {
	sectors, err := listSectors(storage)
	if err != nil {
		fatalJSON(err)
	}
	writePrettyJSON(os.Stdout, sectors)
}

func ensureStorageForCLI(storage string) {
	if err := initStorage(storage); err != nil {
		log.Fatal(err)
	}
	_ = filepath.Separator
}

func metaOrDefaultPieceBlockSize(storage, pieceRoot string, fallback int64) int64 {
	meta, err := readMeta(storage, pieceRoot)
	if err == nil && meta.PieceBlockSize > 0 {
		return meta.PieceBlockSize
	}
	return fallback
}

// handleQuote handles the /filetrust/quote/1.0.0 protocol.
// DO calls this BEFORE depositing escrow or sending the file. VK generates all
// commitment values, saves private credentials keyed by paymentCommitment, and
// returns the public commitments + price so DO can deposit escrow on-chain.
func handleQuote(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	requesterID := requesterIDFromStream(s)
	now := time.Now().UTC()
	if blocked, until := requesterBlockedUntil(requesterID, now); blocked {
		writeJSON(s, QuoteResp{OK: false, Err: fmt.Sprintf("requester temporarily blocked until %s", until.Format(time.RFC3339))})
		return
	}
	r := bufio.NewReader(s)
	var req QuoteReq
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: err.Error()})
		return
	}
	if req.Size <= 0 {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: "invalid size"})
		return
	}
	if req.TransferID == "" {
		nonce, err := randomNonce()
		if err != nil {
			writeJSON(s, QuoteResp{OK: false, Err: "generate durable quote id: " + err.Error()})
			return
		}
		req.TransferID = "ftq_" + strings.TrimPrefix(nonce, "0x")
	}
	if !validTransferID(req.TransferID) {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: "invalid transferId for durable quote"})
		return
	}
	if cfg.MaxPieceSizeBytes > 0 && req.Size > cfg.MaxPieceSizeBytes {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: fmt.Sprintf("piece size %d exceeds VK maxPieceSizeBytes %d", req.Size, cfg.MaxPieceSizeBytes)})
		return
	}
	if req.ServiceEnd <= 0 {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: "invalid serviceEnd"})
		return
	}
	// Every enforceable quote deadline is interpreted by Solidity using
	// block.timestamp. Build all time-dependent quote terms from one chain
	// snapshot so host/validator clock skew cannot make a freshly signed quote
	// already expired on arrival.
	chainNow, chainTimeErr := rpcLatestBlockTimestamp(cfg.RPCURL)
	if chainTimeErr != nil {
		writeJSON(s, QuoteResp{
			OK:  false,
			Err: "temporary blockchain RPC failure — cannot issue a time-valid quote: " + chainTimeErr.Error(),
		})
		return
	}
	if req.ServiceEnd <= chainNow {
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: "serviceEnd is not in the future according to blockchain time"})
		return
	}
	if cfg.MaxServiceDays > 0 {
		maxEnd := chainNow + int64(cfg.MaxServiceDays)*86400
		if req.ServiceEnd > maxEnd {
			markRequesterFailure(requesterID, 1, time.Now().UTC())
			writeJSON(s, QuoteResp{OK: false, Err: fmt.Sprintf("serviceEnd exceeds VK maxServiceDays (%d)", cfg.MaxServiceDays)})
			return
		}
	}
	// Nothing is held, reserved or signed for a request that cannot prove it is
	// the data owner of a real file whose key generation is finished.
	if authErr := authorizeQuoteRequest(cfg, req, time.Now().UTC()); authErr != nil {
		if errors.Is(authErr, ErrRPCUnavailable) {
			writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
				Err: "temporary blockchain RPC failure — cannot verify quote authorization: " + authErr.Error()})
			return
		}
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: authErr.Error()})
		return
	}
	fileHash := quoteFileHash(req.FileID)
	identityHash := quoteReservationIdentityHash(transferIdentity("", requesterID))
	retryingDemand := strings.TrimSpace(req.BlockedDemandID) != "" ||
		strings.TrimSpace(req.BlockedDemandCapability) != ""
	var retryDemand BlockedAdmissionDemand
	if retryingDemand {
		if strings.TrimSpace(req.BlockedDemandID) == "" ||
			strings.TrimSpace(req.BlockedDemandCapability) == "" {
			writeJSON(s, QuoteResp{OK: false, Err: "blocked-demand retry requires both id and capability"})
			return
		}
		confirmed, demandErr := confirmBlockedDemandPending(
			cfg.Storage, req.BlockedDemandID, req.BlockedDemandCapability, time.Now())
		if demandErr != nil {
			writeJSON(s, QuoteResp{OK: false, Err: "blocked-demand retry rejected: " + demandErr.Error()})
			return
		}
		expectedBytes, sizeErr := quoteReservedCapacityBytes(req.Size, cfg)
		if sizeErr != nil || confirmed.RequestedBytes != uint64(expectedBytes) {
			writeJSON(s, QuoteResp{OK: false, Err: "blocked-demand retry size does not match the refused request"})
			return
		}
		expectedScope := blockedDemandSessionScope(cfg.Storage, identityHash)
		if expectedScope == "" || confirmed.SessionScope != expectedScope {
			writeJSON(s, QuoteResp{OK: false, Err: "blocked-demand retry requester scope mismatch"})
			return
		}
		retryDemand = confirmed
		if confirmed.State != BlockedDemandReadyForRetry {
			writeJSON(s, QuoteResp{
				OK: false, Busy: true, RetryAfterSeconds: 5,
				Err:             "blocked demand is still pending actual certified capacity",
				BlockedDemandID: confirmed.DemandID, BlockedDemandState: string(confirmed.State),
				BlockedDemandExpiresAt: confirmed.ExpiresAtUnix,
			})
			return
		}
	}
	// A lost response must recover the same economic obligation, not allocate a
	// second one. This check deliberately precedes current admission/backlog
	// gates because an already-issued quote remains the VK's responsibility.
	transferStateMu.Lock()
	existing, existingFound, existingErr := loadQuoteReservation(cfg.Storage, req.TransferID)
	transferStateMu.Unlock()
	if existingErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "durable quote state is unreadable: " + existingErr.Error()})
		return
	}
	if existingFound {
		if existing.IdentityHash != identityHash || existing.FileHash != fileHash ||
			existing.PieceSize != req.Size || existing.ServiceEnd != req.ServiceEnd {
			markRequesterFailure(requesterID, 1, time.Now().UTC())
			writeJSON(s, QuoteResp{OK: false, Err: "transferId is already bound to different quote metadata"})
			return
		}
		switch verdict := classifyQuoteReservationReuse(existing, chainNow); {
		case verdict.Settled:
			// Terminal, and named: the caller has to handle an already-stored
			// piece and a discharged-without-delivery one differently.
			writeJSON(s, QuoteResp{OK: false,
				Err: "durable quote is no longer available for a new escrow deposit" +
					" (settled as " + verdict.Status + ")",
				QuoteSettledState: verdict.Status})
			return
		case verdict.Busy:
			writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
				Err: "existing durable quote expired and is awaiting authoritative capacity reconciliation"})
			return
		}
		chainReservation, readErr := getCapacityQuoteReservation(cfg, existing.RegistrationCommitment)
		if readErr != nil {
			writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
				Err: "temporary blockchain RPC failure — cannot verify durable quote reservation: " + readErr.Error()})
			return
		}
		if hostErr := reserveHostFilesystemCapacity(cfg, existing); hostErr != nil {
			if (chainReservation.State != capacityQuoteQuoted && chainReservation.State != capacityQuoteActiveTransfer) ||
				preserveHostFilesystemCapacity(cfg, existing) != nil {
				writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
					Err: "durable host filesystem reservation is unavailable: " + hostErr.Error()})
				return
			}
		}
		if existing.Status == quoteReservationPendingChain && chainReservation.State == capacityQuoteNone {
			txHash, reserveErr := reserveCapacityQuoteOnChain(cfg, existing)
			if reserveErr != nil {
				writeJSON(s, QuoteResp{OK: false, Busy: errors.Is(reserveErr, ErrRPCUnavailable), RetryAfterSeconds: 5,
					Err: "recover durable on-chain capacity reservation: " + reserveErr.Error()})
				return
			}
			existing.ReservationTxHash = txHash
			chainReservation, readErr = getCapacityQuoteReservation(cfg, existing.RegistrationCommitment)
			if readErr != nil {
				writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
					Err: "temporary blockchain RPC failure after durable quote recovery: " + readErr.Error()})
				return
			}
		}
		if !capacityQuoteMatches(existing, chainReservation, cfg.VKAddress) {
			writeJSON(s, QuoteResp{OK: false, Err: "durable quote has no matching active on-chain capacity reservation"})
			return
		}
		if existing.Status == quoteReservationPendingChain {
			if err := confirmLocalQuoteReservation(cfg.Storage, existing.TransferID, existing.ReservationTxHash); err != nil {
				writeJSON(s, QuoteResp{OK: false, Err: "confirm recovered durable quote: " + err.Error()})
				return
			}
			existing.Status = quoteReservationQuoted
		}
		if retryingDemand {
			if consumeErr := consumeBlockedDemand(
				cfg.Storage, retryDemand.DemandID, req.BlockedDemandCapability, time.Now()); consumeErr != nil {
				writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
					Err: "quote reservation succeeded but blocked-demand consumption is pending: " + consumeErr.Error()})
				return
			}
		}
		writeJSON(s, quoteResponseFromReservation(existing, cfg.VKEscrowContract))
		markRequesterSuccess(requesterID, time.Now().UTC())
		return
	}
	if cfg.CapacityBytes > 0 {
		if !common.IsHexAddress(cfg.CapacityProofContract) || cfg.FileRegistrationContract == "" {
			writeJSON(s, QuoteResp{OK: false, Err: "capacity-backed quote contracts are not fully configured"})
			return
		}
		state := computeAdmissionState(cfg.Storage, cfg)
		if state.Closed {
			writeJSON(s, QuoteResp{OK: false, Err: state.Reason})
			return
		}
	}
	// A quote is an economic commitment: the DO may deposit escrow immediately
	// after receiving it. The actual durable reservation is made below after all
	// random commitments and signed terms exist.
	identity := transferIdentity("", requesterID)
	lease, retryAfter, admissionErr := transferController(cfg).acquire("upload", identity, "", 0)
	if admissionErr != nil {
		writeJSON(s, QuoteResp{
			OK: false, Busy: true, RetryAfterSeconds: retryAfter, Err: admissionErr.Error(),
		})
		return
	}
	defer lease.Release()

	nullifier, secret, pc, err := GeneratePaymentCommitment()
	if err != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "generate payment commitment: " + err.Error()})
		return
	}
	sizeNonce, sc, err := GenerateSizeCommitment(req.Size)
	if err != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "generate size commitment: " + err.Error()})
		return
	}
	regNull, regSec, regCommitment, err := GenerateRegistrationCommitment()
	if err != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "generate registration commitment: " + err.Error()})
		return
	}
	linkNonce, lc, err := GenerateLinkCommitment(pc, regCommitment)
	if err != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "generate link commitment: " + err.Error()})
		return
	}

	agreedPriceWei := ""
	if cfg.StorageFee > 0 && cfg.SuToWeiRate > 0 {
		durationSec := req.ServiceEnd - chainNow
		if durationSec < 0 {
			durationSec = 0
		}
		const secsPerDay = int64(86400)
		durationDays := (durationSec + secsPerDay - 1) / secsPerDay
		price := storagePriceWeiForBytes(cfg.StorageFee, req.Size, durationDays, cfg.SuToWeiRate)
		agreedPriceWei = price.String()
	}
	if agreedPriceWei == "" || agreedPriceWei == "0" {
		writeJSON(s, QuoteResp{OK: false, Err: "cannot issue enforceable quote with zero price"})
		return
	}
	if strings.TrimSpace(cfg.VKPrivKeyHex) == "" || cfg.ChainID <= 0 ||
		strings.TrimSpace(cfg.VKAddress) == "" || strings.TrimSpace(cfg.VKEscrowContract) == "" {
		writeJSON(s, QuoteResp{OK: false, Err: "VK admission quote signing is not configured"})
		return
	}
	// The zero-price refusal above ran on the storage price alone, so neither the
	// minimum nor the hold fee can make a keeper with no storage fee look
	// enforceable.
	minimumPriceWei, minimumErr := escrowPieceTxCostWei(cfg)
	if minimumErr != nil {
		writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
			Err: "temporary blockchain RPC failure — cannot read the escrow's per-piece cost: " + minimumErr.Error()})
		return
	}
	agreedPriceWei = quotedPriceWei(agreedPriceWei, minimumPriceWei, cfg)
	quoteValidUntil := admissionQuoteValidUntil(chainNow)
	registrationTimeout, timeoutErr := escrowRegistrationTimeoutSeconds(cfg)
	if timeoutErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "read escrow registration timeout: " + timeoutErr.Error()})
		return
	}
	if registrationTimeout > math.MaxInt64 || quoteValidUntil > math.MaxInt64-int64(registrationTimeout) {
		writeJSON(s, QuoteResp{OK: false, Err: "quote reservation deadline overflow"})
		return
	}
	reservationExpiresAt := quoteValidUntil + int64(registrationTimeout)
	reservedCapacityBytes, reserveSizeErr := quoteReservedCapacityBytes(req.Size, cfg)
	if reserveSizeErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: reserveSizeErr.Error()})
		return
	}
	maxRegistrationTimeout, maxTimeoutErr := maximumRegistrationTimeoutSeconds(cfg)
	if maxTimeoutErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "read maximum escrow registration timeout: " + maxTimeoutErr.Error()})
		return
	}
	transferDeadline, deadlineErr := quoteTransferDeadline(
		chainNow, quoteValidUntil, reservedCapacityBytes, cfg, maxRegistrationTimeout,
	)
	if deadlineErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: deadlineErr.Error()})
		return
	}
	if transferDeadline >= req.ServiceEnd {
		writeJSON(s, QuoteResp{OK: false, Err: "serviceEnd is too near for the bounded transfer and registration window"})
		return
	}
	quoteKey, keyErr := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if keyErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "invalid VK admission quote signing key"})
		return
	}
	quoteSignature, signErr := signAdmissionQuoteV2(
		quoteKey, cfg.ChainID, cfg.VKAddress, cfg.VKEscrowContract,
		pc, regCommitment, sc, lc, agreedPriceWei, req.ServiceEnd, quoteValidUntil, transferDeadline,
	)
	if signErr != nil {
		writeJSON(s, QuoteResp{OK: false, Err: "sign admission quote: " + signErr.Error()})
		return
	}

	creds := PaymentCredentials{
		CommitmentHash:         "", // filled in when file is actually stored
		PaymentCommitment:      pc,
		Nullifier:              nullifier,
		Secret:                 secret,
		SizeCommitment:         sc,
		SizeNonce:              sizeNonce,
		PieceSize:              req.Size,
		ServiceEnd:             req.ServiceEnd,
		AgreedPriceWei:         agreedPriceWei,
		RegNullifier:           regNull,
		RegSecret:              regSec,
		RegistrationCommitment: regCommitment,
		LinkNonce:              linkNonce,
		LinkCommitment:         lc,
		QuoteValidUntil:        quoteValidUntil,
		ReservationExpiresAt:   reservationExpiresAt,
		ReservedCapacityBytes:  reservedCapacityBytes,
		TransferDeadline:       transferDeadline,
	}
	if saveErr := SaveQuoteCredentials(cfg.Storage, creds); saveErr != nil {
		log.Printf("[quote] save credentials error: %v", saveErr)
		markRequesterFailure(requesterID, 1, time.Now().UTC())
		writeJSON(s, QuoteResp{OK: false, Err: "failed to save quote credentials"})
		return
	}
	record := quoteReservationRecord{
		Version: quoteReservationRecordVersion, TransferID: req.TransferID,
		IdentityHash: identityHash, FileHash: fileHash, Status: quoteReservationPendingChain,
		PaymentCommitment: pc, SizeCommitment: sc, LinkCommitment: lc, LinkNonce: linkNonce,
		RegistrationCommitment: regCommitment, PieceSize: req.Size,
		ReservedCapacityBytes: reservedCapacityBytes, ServiceEnd: req.ServiceEnd,
		QuoteValidUntil: quoteValidUntil, ReservationExpiresAt: reservationExpiresAt,
		TransferDeadline: transferDeadline,
		AgreedPriceWei:   agreedPriceWei, VKSignature: quoteSignature,
		CapacityProofContract: cfg.CapacityProofContract,
		CreatedAt:             nowRFC3339(), UpdatedAt: nowRFC3339(),
		RetryDemandID: retryDemand.DemandID,
	}
	storeCapacityMu.Lock()
	localReserveErr := reserveLocalQuoteCapacity(cfg, record)
	storeCapacityMu.Unlock()
	if localReserveErr != nil {
		removeUnpublishedQuoteCredentials(cfg.Storage, pc)
		response := QuoteResp{OK: false, Err: localReserveErr.Error()}
		var refusal *blockedAdmissionRefusal
		if errors.As(localReserveErr, &refusal) {
			response.BlockedDemandID = refusal.demand.DemandID
			response.BlockedDemandCapability = refusal.capability
			response.BlockedDemandState = string(refusal.demand.State)
			response.BlockedDemandExpiresAt = refusal.demand.ExpiresAtUnix
		}
		writeJSON(s, response)
		return
	}
	reservationTxHash, chainReserveErr := reserveCapacityQuoteOnChain(cfg, record)
	if chainReserveErr != nil {
		// Release only after an authoritative read proves no reservation exists.
		// RPC ambiguity keeps the durable bytes reserved and fails closed.
		if chainReservation, readErr := getCapacityQuoteReservation(cfg, regCommitment); readErr == nil &&
			chainReservation.State == capacityQuoteNone {
			_ = releaseFailedLocalQuoteReservation(cfg.Storage, req.TransferID)
			removeUnpublishedQuoteCredentials(cfg.Storage, pc)
		}
		writeJSON(s, QuoteResp{OK: false, Busy: errors.Is(chainReserveErr, ErrRPCUnavailable),
			RetryAfterSeconds: 5, Err: "capacity reservation was not confirmed: " + chainReserveErr.Error()})
		return
	}
	if err := confirmLocalQuoteReservation(cfg.Storage, req.TransferID, reservationTxHash); err != nil {
		// The chain reservation remains safe and will expire/reconcile. Do not
		// return a quote whose local recovery record could not be committed.
		writeJSON(s, QuoteResp{OK: false, Err: "on-chain reservation confirmed but local confirmation failed: " + err.Error()})
		return
	}
	record.Status = quoteReservationQuoted
	record.ReservationTxHash = reservationTxHash
	if retryingDemand {
		if consumeErr := consumeBlockedDemand(
			cfg.Storage, retryDemand.DemandID, req.BlockedDemandCapability, time.Now()); consumeErr != nil {
			writeJSON(s, QuoteResp{OK: false, Busy: true, RetryAfterSeconds: 5,
				Err: "quote reservation succeeded but blocked-demand consumption is pending: " + consumeErr.Error()})
			return
		}
	}

	log.Printf("[quote] issued  pc=%s  size=%d  serviceEnd=%d  price=%s",
		truncate(pc, 18), req.Size, req.ServiceEnd, agreedPriceWei)
	writeJSON(s, quoteResponseFromReservation(record, cfg.VKEscrowContract))
	markRequesterSuccess(requesterID, time.Now().UTC())
	maybeSyncAdmissionStatus(cfg)
}

func admissionQuoteValidUntil(chainTimestamp int64) int64 {
	return chainTimestamp + int64((5 * time.Minute).Seconds())
}

// verifyEscrowDeposit calls VKEscrow status views and checks the on-chain deposit
// against quoted terms. In hybrid mode it can accept unfinalized bond-first escrow.
func verifyEscrowDeposit(cfg ServerConfig, creds PaymentCredentials) (int64, error) {
	callStatus := func(fn string) (string, error) {
		selector := ethcrypto.Keccak256([]byte(fn + "(bytes32)"))[:4]
		calldata := make([]byte, 0, 4+32)
		calldata = append(calldata, selector...)
		calldata = append(calldata, hexToBytes32(creds.PaymentCommitment)...)
		result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
			map[string]string{
				"to":   cfg.VKEscrowContract,
				"data": "0x" + hex.EncodeToString(calldata),
			},
			"latest",
		})
		logEthCall("vk:VKEscrow."+fn, cfg.RPCURL, 0, "VKEscrow", fn, cfg.VKEscrowContract, "", statusFromErr(err), map[string]any{
			"payment_commitment": creds.PaymentCommitment,
		})
		if err != nil {
			return "", err
		}
		raw := strings.TrimPrefix(strings.TrimSpace(result), "0x")
		if raw == "" {
			return "", fmt.Errorf("%w: VKEscrow.%s returned empty data", ErrRPCUnavailable, fn)
		}
		return raw, nil
	}

	rawV2, errV2 := callStatus("escrowStatusV2")
	raw := ""
	useV2 := errV2 == nil && len(rawV2) >= 640
	if useV2 {
		raw = rawV2
	} else {
		var errV1 error
		raw, errV1 = callStatus("escrowStatus")
		if errV1 != nil {
			return 0, fmt.Errorf("escrowStatus call failed: %w (v2: %v)", errV1, errV2)
		}
	}
	requiredLength := 512
	statusMethod := "escrowStatus"
	if useV2 {
		requiredLength = 640
		statusMethod = "escrowStatusV2"
	}
	if err := validateABIHexResponse(raw, requiredLength, "VKEscrow."+statusMethod); err != nil {
		return 0, err
	}

	totalAmount, ok := new(big.Int).SetString(raw[0:64], 16)
	if !ok {
		return 0, fmt.Errorf("invalid totalAmount in escrow response")
	}
	if totalAmount.Sign() == 0 {
		return 0, fmt.Errorf("no escrow deposit found for paymentCommitment %s", truncate(creds.PaymentCommitment, 18))
	}

	onChainServiceEnd, ok := new(big.Int).SetString(raw[128:192], 16)
	if !ok {
		return 0, fmt.Errorf("invalid serviceEnd in escrow response")
	}
	onChainSizeCommitment := "0x" + strings.ToLower(raw[192:256])

	expectedSC := strings.ToLower(strings.TrimPrefix(creds.SizeCommitment, "0x"))
	if onChainSizeCommitment != "0x"+expectedSC {
		return 0, fmt.Errorf("sizeCommitment mismatch: on-chain=%s expected=%s", onChainSizeCommitment, creds.SizeCommitment)
	}
	if onChainServiceEnd.Int64() != creds.ServiceEnd {
		return 0, fmt.Errorf("serviceEnd mismatch: on-chain=%d expected=%d", onChainServiceEnd.Int64(), creds.ServiceEnd)
	}

	deadlineRaw, deadlineErr := callStatus("registrationDeadlineOf")
	if deadlineErr != nil {
		return 0, fmt.Errorf("registration deadline unavailable: %w", deadlineErr)
	}
	if err := validateABIHexResponse(deadlineRaw, 64, "VKEscrow.registrationDeadlineOf"); err != nil {
		return 0, err
	}
	deadlineValue, ok := new(big.Int).SetString(deadlineRaw[0:64], 16)
	if !ok || deadlineValue.Sign() <= 0 {
		return 0, fmt.Errorf("invalid registration deadline")
	}
	registrationDeadline := deadlineValue.Int64()
	if creds.TransferDeadline > 0 && registrationDeadline != creds.TransferDeadline {
		return 0, fmt.Errorf(
			"registration deadline mismatch: on-chain=%d signed=%d",
			registrationDeadline, creds.TransferDeadline,
		)
	}
	chainTimestamp, blockErr := rpcLatestBlockTimestamp(cfg.RPCURL)
	if blockErr != nil {
		return 0, fmt.Errorf("latest chain time unavailable: %w", blockErr)
	}
	if chainTimestamp > registrationDeadline {
		return 0, fmt.Errorf("registration deadline elapsed")
	}

	finalized := true
	finalizeBy := int64(0)
	if useV2 {
		fv, ok := new(big.Int).SetString(raw[512:576], 16)
		if !ok {
			return 0, fmt.Errorf("invalid finalized flag in escrowStatusV2 response")
		}
		finalized = fv.Sign() != 0
		fb, ok := new(big.Int).SetString(raw[576:640], 16)
		if !ok {
			return 0, fmt.Errorf("invalid finalizeBy in escrowStatusV2 response")
		}
		finalizeBy = fb.Int64()
	}

	if !finalized {
		if !cfg.EscrowAllowUnfinalizedStores {
			return 0, fmt.Errorf("escrow not finalized yet")
		}
		if useV2 && finalizeBy > 0 && chainTimestamp > finalizeBy {
			return 0, fmt.Errorf("escrow finalize deadline elapsed")
		}
		// Hybrid mode accepts bond-first escrow before finalization.
		return registrationDeadline, nil
	}

	// Finalized escrow: enforce quoted total.
	if creds.AgreedPriceWei != "" {
		agreed, ok := new(big.Int).SetString(creds.AgreedPriceWei, 10)
		if !ok {
			return 0, fmt.Errorf("invalid agreedPriceWei in credentials")
		}
		if totalAmount.Cmp(agreed) < 0 {
			return 0, fmt.Errorf("escrow totalAmount %s < agreedPriceWei %s", totalAmount, agreed)
		}
	}

	return registrationDeadline, nil
}

// validateABIHexResponse validates a fixed-width ABI response before any field
// is sliced from it. RPC gateways may return null, "0x", truncated data, or
// malformed hex during overload; none of those responses may reach indexing
// code or crash the VK.
func validateABIHexResponse(raw string, minimumHexLength int, operation string) error {
	raw = strings.TrimPrefix(strings.TrimSpace(raw), "0x")
	if len(raw) < minimumHexLength {
		return fmt.Errorf(
			"%w: %s returned truncated data: got %d hex chars, need at least %d",
			ErrRPCUnavailable, operation, len(raw), minimumHexLength,
		)
	}
	if len(raw)%2 != 0 {
		return fmt.Errorf("%w: %s returned odd-length hex data", ErrRPCUnavailable, operation)
	}
	if len(raw)%64 != 0 {
		return fmt.Errorf(
			"%w: %s returned non-word-aligned ABI data: got %d hex chars",
			ErrRPCUnavailable, operation, len(raw),
		)
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return fmt.Errorf("%w: %s returned malformed hex data: %v", ErrRPCUnavailable, operation, err)
	}
	return nil
}

// handleDelete processes a DO-requested file deletion via the DeleteProtocol stream.
// Flow owned by this stream:
//  1. Validate credentials and deletion authorization.
//  2. Persist the stable commitment-based lifecycle identity.
//  3. Call/observe registerFileDeletion and return acceptance.
//
// The stream owns only durable validation and on-chain declaration. Physical
// deletion, proof, confirmation, capacity release, and cleanup are resumed by
// the lifecycle worker independently of this connection.
func handleDelete(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	r := bufio.NewReader(s)
	var req DeleteReq
	if err := json.NewDecoder(r).Decode(&req); err != nil {
		writeJSON(s, DeleteResp{Error: "decode request: " + err.Error()})
		return
	}
	if req.CommitmentHash == "" {
		// Explicit permanent rejection: a missing commitment can never succeed on retry.
		writeJSON(s, DeleteResp{Terminal: true, ErrorCode: "commitment_required", Error: "commitmentHash required"})
		return
	}

	// Finding 3 (strict capability cutover): a client that does not implement the F.1
	// durable re-drive loop cannot re-send this secret-bearing request while the VK holds
	// the deletion as accepted_queued. If the VK persisted accepted_queued for such a
	// client, ANY declaration failure or crash — even for a sole partition owner — would
	// strand the deletion permanently undeclared. Therefore the new VK REJECTS every such
	// request BEFORE any persistence, with a stable permanent protocol error. Old DO + new
	// VK is NOT a supported deletion mode: deploy F.1-capable DOs first. (New DO + old VK
	// is unaffected — an old VK ignores this field and declares synchronously.)
	if !req.RedriveCapable {
		writeJSON(s, DeleteResp{
			OK: false, Terminal: true,
			ErrorCode:  "deletion_redrive_required",
			DeletionID: strings.ToLower(strings.TrimSpace(req.CommitmentHash)),
			Error:      "deletion requires a client that supports durable deletion re-drive; upgrade the data owner before deleting",
		})
		return
	}

	creds, err := LoadPaymentCredentials(cfg.Storage, req.CommitmentHash)
	if err != nil {
		// Explicit permanent rejection: unknown commitment / no credentials.
		writeJSON(s, DeleteResp{Terminal: true, Error: "credentials not found for commitmentHash: " + err.Error()})
		return
	}
	// Two independent questions, and both must be answered.
	//
	// The secret proves the sender holds something the owner was given. It does
	// not say who they are and it never expires, so on its own a copy taken from
	// a log or an old backup destroys the data years later.
	//
	// The signature proves who is asking, and the chain says whether that
	// identity owns the file. Neither check substitutes for the other: the
	// signature stops a leaked secret, the secret stops an owner's key being
	// enough on its own.
	var deleteFileID string
	if meta, metaErr := readMeta(cfg.Storage, creds.PieceRoot); metaErr == nil {
		deleteFileID = meta.FileID
	}
	if err := authorizeDeleteRequest(cfg, req, deleteFileID); err != nil {
		writeJSON(s, DeleteResp{Terminal: true, Error: "deletion authorization failed: " + err.Error()})
		return
	}

	// A piece stored without a deletion secret has nothing to check the second
	// half against, and there is no safe way to authorize with nothing. Refusing
	// costs cleanup; accepting cost the data.
	if creds.DeletionAuthHash == "" {
		writeJSON(s, DeleteResp{Terminal: true,
			Error: "no deletion authorization was recorded for this commitment; " +
				"this piece cannot be deleted over the network"})
		return
	}
	{
		secret := strings.TrimPrefix(strings.TrimSpace(req.DeletionAuthSecret), "0x")
		decoded, decodeErr := hex.DecodeString(secret)
		if decodeErr != nil || len(decoded) != 32 ||
			!strings.EqualFold(ethcrypto.Keccak256Hash(decoded).Hex(), creds.DeletionAuthHash) {
			// Explicit permanent rejection: invalid authorization secret.
			writeJSON(s, DeleteResp{Terminal: true, Error: "invalid deletion authorization secret"})
			return
		}
	}
	// E.1: durable acceptance happens below WITHOUT any processing-budget gate, so a
	// valid deletion is never refused as "busy". Only background processing (0.1's
	// mutate/seal/prove, and E.2's budget) is concurrency-limited.

	// Idempotently persist accepted_queued before any further work. One journal file
	// per commitment: retries never create duplicate entries and never regress an
	// already-advanced phase.
	operation, operationExists, operationErr := readDeletionLifecycleOperation(cfg.Storage, req.CommitmentHash)
	if operationErr != nil {
		writeJSON(s, DeleteResp{Error: "read deletion lifecycle: " + operationErr.Error()})
		return
	}
	if !operationExists {
		operation = DeletionLifecycleOperation{
			Version: lifecycleJournalVersion, CommitmentHash: req.CommitmentHash,
			PieceRoot: creds.PieceRoot, Phase: "accepted_queued", CreatedAt: nowRFC3339(),
		}
		if sector, found, findErr := sectorForDeletionOperation(cfg.Storage, operation); findErr != nil {
			writeJSON(s, DeleteResp{Error: "locate deletion sector: " + findErr.Error()})
			return
		} else if found {
			operation.SectorID = sector.SectorID
			operation.DeadlineIndex = sector.DeadlineIndex
			operation.PartitionIndex = sector.PartitionIndex
		}
	}
	if strings.TrimSpace(operation.Phase) == "" {
		operation.Phase = "accepted_queued"
	}
	if err := writeDeletionLifecycleOperation(cfg.Storage, operation); err != nil {
		writeJSON(s, DeleteResp{Error: "persist deletion acceptance: " + err.Error()})
		return
	}

	// Best-effort on-chain declaration state. A transient RPC failure does NOT refuse
	// acceptance: the deletion is durably accepted_queued and reported retryable so the
	// DO re-drives.
	declared, confirmed, statusErr := deletionStatusOnChain(cfg, req.CommitmentHash)
	if statusErr == nil && declared {
		// Already declared (a prior request/crash): sync the durable phase.
		if mErr := markDeletionDeclaredPending(cfg.Storage, &operation); mErr != nil {
			recordDeletionLifecycleError(cfg.Storage, req.CommitmentHash, mErr)
		}
	} else if statusErr == nil && !confirmed {
		// 0.1: declare on-chain iff this op is the durable FIFO owner, after
		// revalidating coordinates/successor version. Non-owner → stays accepted_queued
		// and the DO re-drives with the secret until ownership reaches it. Declaration
		// is idempotent and crash-safe (re-checks on-chain state before/after sending).
		if didDeclare, decErr := attemptOwnerDeletionDeclaration(cfg, &operation, req.DeletionAuthSecret); decErr != nil {
			// Transient failure: stay accepted_queued and recoverable; never falsely
			// marked declared. The error never contains the secret.
			recordDeletionLifecycleError(cfg.Storage, req.CommitmentHash, decErr)
		} else if didDeclare {
			declared = true
		}
	}

	// Wake background reconciliation (a no-op while still accepted_queued). No
	// processing lease is held across the declaration/proof lifecycle.
	triggerDeletionLifecycleRecovery(cfg, req.CommitmentHash)

	writeJSON(s, deletionAcceptanceResponse(req.CommitmentHash, declared, confirmed))
}

// deletionAcceptanceResponse builds the acceptance receipt. accepted_queued is always
// reported with declared=false and retryable=true so the DO's durable monitor re-sends
// the secret-bearing request until on-chain declaration is confirmed.
func deletionAcceptanceResponse(commitmentHash string, declared, confirmed bool) DeleteResp {
	phase := "accepted_queued"
	switch {
	case confirmed:
		phase = "confirmed"
	case declared:
		phase = "declared_pending"
	}
	return DeleteResp{
		OK: true, Accepted: true,
		DeletionID: strings.ToLower(strings.TrimSpace(commitmentHash)),
		Declared:   declared,
		Retryable:  !declared && !confirmed,
		Pending:    !confirmed,
		Phase:      phase,
	}
}

func handleHasPiece(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	var req HasPieceReq
	if err := json.NewDecoder(bufio.NewReader(s)).Decode(&req); err != nil {
		writeJSON(s, HasPieceResp{Error: "decode request: " + err.Error()})
		return
	}
	if req.PieceRoot == "" {
		writeJSON(s, HasPieceResp{Error: "pieceRoot required"})
		return
	}
	pieceRoot := normalizeRoot(req.PieceRoot)
	if err := validateRoot(pieceRoot); err != nil {
		writeJSON(s, HasPieceResp{Error: "invalid pieceRoot"})
		return
	}

	pending, pendingErr := pieceDeletionPending(cfg.Storage, pieceRoot)
	if pendingErr != nil {
		writeJSON(s, HasPieceResp{Error: "piece deletion state unavailable"})
		return
	}
	has, deleted, commitmentHash, commitmentNonce := findPieceStatus(cfg.Storage, pieceRoot)
	if pending {
		has = false
	}
	writeJSON(s, HasPieceResp{
		Has:             has,
		Deleted:         deleted,
		DeletionPending: pending,
		CommitmentHash:  commitmentHash,
		CommitmentNonce: commitmentNonce,
	})
}

func handleInfo(s network.Stream, cfg ServerConfig) {
	defer s.Close()
	info := getStorageInfo(cfg.Storage, cfg.CapacityBytes)
	info = enrichStorageInfoAdmission(info, cfg.Storage, cfg)
	info.Transfers = transferController(cfg).snapshot()
	writeJSON(s, info)
}

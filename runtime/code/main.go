package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mr-tron/base58/base58"
)

func main() {
	// Presentation only: reformats whole log lines on their way to stdout and
	// changes nothing about what is logged. VK_LOG_FORMAT=raw restores the
	// original format; NO_COLOR or VK_LOG_COLOR=never drops the colour.
	if consoleFormattingEnabled() {
		log.SetFlags(log.LstdFlags)
		log.SetOutput(&consoleWriter{out: os.Stdout, color: consoleColorEnabled()})
	}

	mode := flag.String("mode", "server", "server | store | get | prove | quote | info | delete | gc | expired-gc | sectors | sector-proof | proof-daemon")
	listen := flag.String("listen", "/ip4/0.0.0.0/tcp/0", "libp2p listen multiaddr")
	storage := flag.String("storage", "storage", "VK storage directory")
	peerAddr := flag.String("peer", "", "target VK multiaddr ending with /p2p/<peerId>")
	filePath := flag.String("file", "", "file path for store/get output")
	pieceRoot := flag.String("piece-root", "", "pieceRoot / Merkle root identifier")
	cid := flag.String("cid", "", "legacy alias for --piece-root")
	fileID := flag.String("file-id", "", "optional FileTrust fileId")
	pieceIndex := flag.Int("piece-index", 0, "optional FileTrust piece index")
	serviceEnd := flag.Int64("service-end", 0, "optional Unix service end for this piece subscription")
	requester := flag.String("requester", "", "requester wallet address for authorized get")
	sig := flag.String("sig", "", "Ethereum signature authorizing get")
	issuedAt := flag.Int64("issued-at", 0, "Unix timestamp used in signed get request")
	// Owner recovery: an upload id names one upload's sealed copy, and the
	// sealed blob itself arrives base64-encoded because it is opaque bytes.
	recoveryUploadID := flag.String("recovery-upload-id", "", "upload id for a sealed recovery copy")
	recoverySealed := flag.String("recovery-sealed", "", "base64 sealed recovery copy to store; empty fetches")
	rpcURL := flag.String("rpc-url", "", "Ethereum JSON-RPC URL used by VK server for ACL checks")
	aclAddress := flag.String("acl-address", "", "AccessControlFT contract address used by VK server")
	allowOpenReads := flag.Bool("allow-unauthenticated-reads", false,
		"Serve every stored piece to anyone, with no access-control check. Closed test networks only.")
	allowOpenWrites := flag.Bool("allow-unauthenticated-writes", false,
		"Accept uploads without confirming the uploader owns the file. Closed test networks only.")
	allowUnverifiedPayments := flag.Bool("allow-unverified-payments", false,
		"Store pieces without confirming on chain that they were paid for. Closed test networks only.")
	allowLegacyUploads := flag.Bool("allow-legacy-unauthenticated-uploads", false,
		"Serve the v2 upload protocol, which performs no authorization at all. Closed test networks only.")
	olderHours := flag.Int("older-hours", 0, "for gc: delete pieces older than this many hours")
	pieceBlockSize := flag.Int64("piece-block-size", DefaultPieceBlockSize, "piece Merkle block size in bytes")
	maxPieceSizeBytes := flag.Int64("max-piece-size-bytes", DefaultMaxPieceSizeBytes, "maximum accepted piece size in bytes (0 = unlimited)")
	maxConcurrentUploads := flag.Int("max-concurrent-uploads", DefaultMaxConcurrentUploads, "maximum simultaneous upload handlers")
	maxConcurrentDownloads := flag.Int("max-concurrent-downloads", DefaultMaxConcurrentDownloads, "maximum simultaneous download handlers")
	maxQueuedTransfers := flag.Int("max-queued-transfers", DefaultMaxQueuedTransfers, "maximum upload/download requests waiting for admission")
	maxTransfersPerPeer := flag.Int("max-transfers-per-peer", DefaultMaxTransfersPerPeer, "maximum simultaneous admitted transfers per remote peer or wallet")
	maxTemporaryUploadBytes := flag.Int64("max-temporary-upload-bytes", 0, "maximum bytes reserved by resumable partial uploads (0 = derive from declared capacity)")
	transferQueueWaitSeconds := flag.Int64("transfer-queue-wait-seconds", DefaultTransferQueueWaitSeconds, "seconds a transfer may wait for admission before receiving busy")
	transferRetryAfterSeconds := flag.Int64("transfer-retry-after-seconds", DefaultTransferRetryAfterSeconds, "retry delay returned when transfer admission is busy")
	partialUploadTTLSeconds := flag.Int64("partial-upload-ttl-seconds", DefaultPartialUploadTTLSeconds, "retention for incomplete resumable uploads")
	completedTransferTTLSeconds := flag.Int64("completed-transfer-ttl-seconds", DefaultCompletedTransferTTLSeconds, "retention for completed transfer responses used by idempotent resume")
	quoteReservationQuantumBytes := flag.Int64("quote-reservation-quantum-bytes", DefaultQuoteReservationQuantumBytes, "privacy-preserving byte quantum for authoritative quote capacity reservations")
	maxOutstandingQuoteReservations := flag.Int("max-outstanding-quote-reservations", DefaultMaxOutstandingQuoteReservations, "maximum globally outstanding durable quote reservations")
	maxOutstandingQuotesPerIdentity := flag.Int("max-outstanding-quotes-per-identity", DefaultMaxOutstandingQuotesPerIdentity, "maximum outstanding durable quotes per remote identity")
	maxOpenQuotesPerFile := flag.Int("max-open-quotes-per-file", DefaultMaxOpenQuotesPerFile, "maximum outstanding durable quotes for one file")
	maxUnusedQuotesPerFile := flag.Int("max-unused-quotes-per-file", DefaultMaxUnusedQuotesPerFile, "unused (never paid and sent) quotes one file may leave within the window before it is refused")
	unusedQuoteWindowSeconds := flag.Int64("unused-quote-window-seconds", DefaultUnusedQuoteWindowSeconds, "window over which unused quotes per file are counted")
	quoteHoldGas := flag.Int64("quote-hold-gas", DefaultQuoteHoldGas, "gas of the keeper's hold and release transactions, charged at --fixed-gas-price-wei inside every quoted price (0 = no hold fee)")
	quoteReservationReconcileSeconds := flag.Int64("quote-reservation-reconcile-seconds", DefaultQuoteReservationReconcileSeconds, "seconds between authoritative quote reservation reconciliation scans")
	quoteTransferMinBytesPerSecond := flag.Int64("quote-transfer-min-bytes-per-second", DefaultQuoteTransferMinBytesPerSecond, "minimum sustained transfer rate used to derive signed registration deadlines")
	quoteTransferRecoveryGraceSeconds := flag.Int64("quote-transfer-recovery-grace-seconds", DefaultQuoteTransferRecoveryGraceSeconds, "additional signed recovery time for a resumable transfer")
	filesystemReserveBytes := flag.Int64("filesystem-reserve-bytes", 0, "hard unsellable filesystem reserve (0 derives proof/upload workspace safely)")
	proofTransferReservePercent := flag.Int("proof-transfer-reserve-percent", DefaultProofTransferReservePercent, "deprecated compatibility option; proof work no longer reduces transfer concurrency")
	proofBackgroundMinWorkers := flag.Int("proof-background-min-workers", DefaultProofBackgroundMinWorkers, "minimum background proof/cache workers while foreground traffic is active")
	proofBackgroundMaxWorkers := flag.Int("proof-background-max-workers", DefaultProofBackgroundMaxWorkers, "maximum background proof/cache workers while idle (0 = available CPUs)")
	proofBackgroundBusyCPUPercent := flag.Int("proof-background-busy-cpu-percent", DefaultProofBackgroundBusyCPUPercent, "average CPU share per background worker while foreground traffic is active")
	proofDeadlineConservativeBoundSeconds := flag.Int("proof-deadline-conservative-bound-seconds", DefaultProofDeadlineConservativeBoundSeconds, "cold bound assumed for one protected storage-deadline proof before measured history calibrates it down")
	sectorMaxPieces := flag.Int("sector-max-pieces", DefaultSectorMaxPieces, "maximum piece roots per local VK sector")
	sectorLifetimeDays := flag.Int("sector-lifetime-days", DefaultSectorLifetimeDays, "default local VK sector lifetime")
	zkBlockSize := flag.Int64("zk-block-size", DefaultZKBlockSize, "ZK sector proof block size in bytes")
	zkTreeDepth := flag.Int("zk-tree-depth", DefaultZKTreeDepth, "fixed ZK sector Merkle tree depth")
	allowSectorExtend := flag.Bool("allow-sector-extend", true, "allow open sector expiration extension to cover a piece serviceEnd")
	sectorMaxExpirationExtension := flag.Int64("sector-max-expiration-extension", DefaultSectorMaxExpirationExtension, "max seconds to extend an open sector expiration for a new piece (0 = default 7 days)")
	sectorAllowLargeMixing := flag.Bool("sector-allow-large-mixing", false, "allow placing pieces in sectors whose expiration bucket is much larger than the piece needs")
	sectorID := flag.String("sector-id", "", "sector id for sector-proof")
	round := flag.Uint64("round", 0, "proof round for sector-proof; 0 means current daily round")
	challengeCount := flag.Int("challenge-count", 1, "challenge count for sector-proof")
	challengeSeed := flag.String("challenge-seed", "", "optional challenge seed for sector-proof")
	zkProverCmd := flag.String("zk-prover-cmd", "", "external ZK prover command that reads JSON stdin and writes JSON stdout")
	chainProofCmd := flag.String("chain-proof-cmd", "", "external chain command for StorageProofSC; reads JSON stdin and writes JSON stdout")
	chainCommandTimeoutSeconds := flag.Int64("chain-command-timeout-seconds", int64(defaultChainProofCommandTimeout/time.Second), "maximum seconds for one StorageProof chain helper call")
	proofPeriodSeconds := flag.Int64("proof-period-seconds", 24*60*60, "proof period in seconds")
	proofPollSeconds := flag.Int64("proof-poll-seconds", 60, "proof daemon poll interval in seconds")
	proofOnce := flag.Bool("proof-once", false, "run one proof-daemon scan and exit")
	deadlineCount := flag.Int("deadline-count", 0, "number of proof deadlines per proof period (0 = disable partition mode)")
	partitionMaxSectors := flag.Int("partition-max-sectors", 16, "maximum sectors per partition (circuit capacity)")
	partitionProverCmd := flag.String("partition-prover-cmd", "", "external ZK prover command for partition proofs")
	deterministicChallenge := flag.Bool("deterministic-challenge", false, "use single-tx deterministic partition proof (no openPartitionChallenge tx)")
	vkPrivKeyHex := flag.String("vk-private-key", "", "Ethereum private key (hex) used to sign private storage receipts returned to DO")
	vkPrivKeyFile := flag.String("vk-private-key-file", "", "Owner-only file containing the VK signing key (preferred over a secret argument)")
	chainID := flag.Int64("chain-id", 0, "EVM chain id written into receipts (0 = disable receipt signing even if key is set)")
	storageProofContract := flag.String("storage-proof-contract", "", "StorageProofSC address written into receipts")
	capacityProofContract := flag.String("capacity-proof-contract", "", "CapacityProofSC address used for authoritative blinded capacity reservations")
	fileRegistrationContract := flag.String("file-registration-contract", "", "FileRegistrationSC address; when set VK calls registerFileStorage() after each store")
	deletionReleaseContract := flag.String("deletion-release-contract", "", "DeletionReleaseSC address used for deletion operation reconciliation")
	commitmentNonce := flag.String("commitment-nonce", "", "0x-prefixed 32-byte hex nonce (generated by DO); used in client 'store' mode to compute commitmentHash = keccak256(pieceRoot || nonce)")
	commitmentHash := flag.String("commitment-hash", "", "0x-prefixed 32-byte commitment hash; used in 'delete' mode to identify the piece to delete")
	deletionAuthHash := flag.String("deletion-auth-hash", "", "0x-prefixed 32-byte keccak256 hash of a DO-held deletion secret; used in client 'store' mode")
	deletionAuthSecret := flag.String("deletion-auth-secret", "", "0x-prefixed 32-byte DO deletion secret; used in 'delete' mode")
	deploymentManifestPath := flag.String("deployment-manifest", "", "path to the versioned deployment manifest; when set, VK startup rejects a mismatched chain id / contract addresses / runtime code hashes / ABI / wiring")
	deployedAddressesPath := flag.String("deployed-addresses", "", "path to deployed_addresses.json; when set with --deployment-manifest, its hash and addresses are verified against the manifest")
	legacySnapshotProtocol := flag.Bool("legacy-snapshot-protocol", false, "EXPLICITLY select the legacy snapshot contract protocol (no frozenSnapshotNonce); deployment preparation only")
	quiesceState := flag.String("quiesce-state", "status", "in 'quiesce-freezes' mode: on, off, or status")
	deleteRequester := flag.String("delete-requester", "", "data-owner wallet authorizing a deletion")
	deleteIssuedAt := flag.Int64("delete-issued-at", 0, "Unix timestamp used in the signed deletion authorization")
	deleteSig := flag.String("delete-sig", "", "Ethereum signature authorizing the deletion")
	redriveCapable := flag.Bool("redrive-capable", false, "in 'delete' mode: signals the client implements the durable deletion re-drive loop (re-sends the request while the VK reports accepted_queued/declared=false)")
	paymentCommitment := flag.String("payment-commitment", "", "paymentCommitment returned by VK in quote mode; include in 'store' mode so VK verifies the escrow deposit")
	fileFormat := flag.String("file-format", "", "optional file format hint stored by VK alongside the piece (e.g. zip)")
	transferID := flag.String("transfer-id", "", "stable resumable transfer identifier")
	blockedDemandID := flag.String("blocked-demand-id", "", "private blocked-admission demand id returned by a refused quote")
	blockedDemandCapability := flag.String("blocked-demand-capability", "", "private capability for a normal blocked-demand quote retry")
	clientIdentityKey := flag.String("client-identity-key", "", "optional mode-0600 libp2p private-key path for stable multi-step client identity")
	uploader := flag.String("uploader", "", "data-owner wallet authorizing an upload transfer")
	transferIssuedAt := flag.Int64("transfer-issued-at", 0, "Unix timestamp used in signed upload authorization")
	transferSig := flag.String("transfer-sig", "", "Ethereum signature authorizing upload transfer metadata")
	expectedPieceRoot := flag.String("expected-piece-root", "", "DO-computed merkle-sha256-v1 root required for store")
	expectedPieceBlockSize := flag.Int64("expected-piece-block-size", 0, "block size used for --expected-piece-root")
	pieceSize := flag.Int64("size", 0, "piece size in bytes; used in 'quote' mode to request payment commitments from VK")
	vkRegistryContract := flag.String("vk-registry-contract", "", "VaultKeeperRegistry address; when set VK self-registers on startup using its own private key")
	vkRegistryABI := flag.String("vk-registry-abi", "", "path to VaultKeeperRegistry ABI JSON file for self-registration")
	advertiseIP := flag.String("advertise-ip", "127.0.0.1", "IP address advertised in the discovery record and its on-chain endpoint hash; auto finds the public internet address, proves it with independent keepers and keeps it current")
	publicAddrCheckSeconds := flag.Int64("public-addr-check-seconds", DefaultPublicAddrCheckSeconds, "auto address: seconds between light checks for a new address")
	publicAddrFullCheckSeconds := flag.Int64("public-addr-full-check-seconds", DefaultPublicAddrFullCheckSeconds, "auto address: seconds between full proofs of the published address")
	publicAddrMinChangeSeconds := flag.Int64("public-addr-min-change-seconds", DefaultPublicAddrMinChangeSeconds, "auto address: minimum seconds between two published changes (each is an on-chain update)")
	publicAddrEchoURLs := flag.String("public-addr-echo-urls", strings.Join(DefaultPublicAddrEchoURLs, ","), "auto address: comma-separated what-is-my-IP services, one vote each")
	publicAddrHelpers := flag.Int("public-addr-helpers", DefaultPublicAddrHelpers, "auto address: independent keepers asked to call this keeper back")
	publicAddrPortMapping := flag.Bool("public-addr-port-mapping", true, "auto address: ask a home router (UPnP / NAT-PMP) to open the listen port")
	reachHelper := flag.Bool("reach-helper", true, "call other keepers back at their own address when they ask, so they can prove it")
	storageFee := flag.Int64("storage-fee", 0, "storage fee in SU per GB per day — registered in VaultKeeperRegistry and used for agreedPriceWei calculation")
	maxServiceDays := flag.Uint64("max-service-days", 0, "maximum service duration VK accepts in days (0 = unlimited); registered in VaultKeeperRegistry")
	suToWeiRate := flag.Int64("su-to-wei-rate", 0, "Wei per SU; same value as RewardManager.suToWeiRate — used to convert storageFee SU amounts to Wei for escrow deposits")
	fixedGasPriceWei := flag.Int64("fixed-gas-price-wei", 1_000_000, "fixed gas price in wei for local FileTrust transactions")
	stakeWei := flag.String("stake-wei", "0", "stake amount in wei sent with registerVaultKeeper (0 = no stake)")
	vkEscrowContract := flag.String("vk-escrow-contract", "", "VKEscrow contract address; when set VK verifies DO escrow deposit before accepting file")
	escrowAllowUnfinalizedStores := flag.Bool("escrow-allow-unfinalized-stores", false, "allow bond-first escrow deposits before finalization (hybrid escrow mode)")
	capacityBytes := flag.Int64("capacity-bytes", 0, "storage capacity in bytes to commit as a provable capacity sector (0 = disabled)")
	capacitySlotSizeBytes := flag.Int64("capacity-slot-size-bytes", 0, "maximum bytes per stable capacity slot/sector (0 = automatic bounded rolling slots)")
	capacityProofDebounceSeconds := flag.Int64("capacity-proof-debounce-seconds", DefaultCapacityProofDebounceSeconds, "quiet/idle delay before opportunistically closing a capacity batch")
	capacityProofMaxBatchSeconds := flag.Int64("capacity-proof-max-batch-seconds", DefaultCapacityProofMaxBatchSeconds, "maximum continuous capacity batch window")
	capacityProofMaxPendingMutations := flag.Int("capacity-proof-max-pending-mutations", DefaultCapacityProofMaxPendingMutations, "pending mutation count service objective")
	capacityProofMaxPendingBytes := flag.Int64("capacity-proof-max-pending-bytes", DefaultCapacityProofMaxPendingBytes, "pending changed-byte service objective")
	capacityProofMaxDivergenceBytes := flag.Int64("capacity-proof-max-divergence-bytes", DefaultCapacityProofMaxDivergenceBytes, "maximum live-versus-proved capacity divergence")
	capacityProofMaxTouchedPartitions := flag.Int("capacity-proof-max-touched-partitions", DefaultCapacityProofMaxTouchedPartitions, "touched partition threshold for closing a batch")
	capacityProofMaxOldestMutationSeconds := flag.Int64("capacity-proof-max-oldest-mutation-seconds", DefaultCapacityProofMaxOldestMutationSeconds, "maximum age of the oldest unproved mutation")
	capacityProofMaxQueueDepth := flag.Int("capacity-proof-max-queue-depth", DefaultCapacityProofMaxQueueDepth, "proof queue depth that forces capacity batch closure")
	capacityProofMaxConsecutiveFailedEpochs := flag.Int("capacity-proof-max-consecutive-failed-epochs", DefaultCapacityProofMaxConsecutiveFailedEpochs, "failed epoch service objective")
	capacityProofSubmissionSafetySeconds := flag.Int64("capacity-proof-submission-safety-seconds", DefaultCapacityProofSubmissionSafetySeconds, "reserved chain submission/confirmation time in freshness calculations")
	resumeCapacity := flag.Bool("resume-capacity", false, "after crash: verify existing capacity sector + ZK cache before rebuilding dummy free-space data")
	forceCapacityRebuild := flag.Bool("force-capacity-rebuild", false, "always rebuild capacity sectors and ZK caches from scratch (skip integrity reuse)")
	admissionMarginBytes := flag.Int64("admission-margin-bytes", 0, "bytes subtracted from fresh certified free capacity after live reservations (0 = 100 MiB)")
	syncAdmissionToRegistry := flag.Bool("sync-admission-to-registry", true, "publish admission open/closed status to VaultKeeperRegistry")
	discoveryURLs := flag.String("discovery", "", "comma-separated FileTrust discovery node URLs")
	discoveryTTLSeconds := flag.Int64("discovery-ttl-seconds", DefaultDiscoveryTTLSeconds, "seconds before a discovery record expires")
	discoveryHeartbeatSeconds := flag.Int64("discovery-heartbeat-seconds", DefaultDiscoveryHeartbeatSeconds, "seconds between discovery heartbeats")
	transactionLogPath := flag.String("transaction-log-path", "", "JSONL transaction log path")
	logMaxMB := flag.Int64("log-max-mb", defaultLogMaxMB, "rotate a log once it reaches this size")
	logKeepDays := flag.Int("log-keep-days", defaultLogKeepDays, "delete gzipped logs older than this")
	logMaxTotalMB := flag.Int64("log-max-total-mb", defaultLogMaxTotalMB, "cap the whole log folder at this size")
	flag.Parse()
	loadedKey, keyErr := loadSigningKeyFile(*vkPrivKeyFile, *vkPrivKeyHex)
	if keyErr != nil {
		log.Fatal(keyErr)
	}
	*vkPrivKeyHex = loadedKey

	// A.0: the frozen-snapshot nonce identity is mandatory by default. The pre-A.0
	// contract protocol (no nonce) is only honoured when explicitly selected here or via
	// FILETRUST_LEGACY_SNAPSHOT_PROTOCOL=1; it is never silently entered.
	if *legacySnapshotProtocol ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("FILETRUST_LEGACY_SNAPSHOT_PROTOCOL")), "1") ||
		strings.EqualFold(strings.TrimSpace(os.Getenv("FILETRUST_LEGACY_SNAPSHOT_PROTOCOL")), "true") {
		requireSnapshotNonceIdentity = false
		// A.1: the local generation identity travels with the same legacy switch. When the
		// pre-A.0/A.1 protocol is explicitly selected, zero generations are tolerated and the
		// generation identity check is not enforced.
		requirePartitionGenerationIdentity = false
		log.Printf("[snapshot] WARNING: legacy snapshot protocol selected; frozenSnapshotNonce and local generation identity are NOT enforced")
	}

	if env := strings.TrimSpace(os.Getenv("FILETRUST_RESUME_CAPACITY")); env == "1" || strings.EqualFold(env, "true") {
		*resumeCapacity = true
	}
	if env := strings.TrimSpace(os.Getenv("FILETRUST_FORCE_CAPACITY_REBUILD")); env == "1" || strings.EqualFold(env, "true") {
		*forceCapacityRebuild = true
	}
	if strings.TrimSpace(os.Getenv(proofHostLockPathEnv)) == "" &&
		(*mode == "server" || *mode == "proof-daemon" || *mode == "sector-proof") {
		storagePath, err := filepath.Abs(*storage)
		if err != nil {
			log.Fatalf("resolve storage path for proof host lock: %v", err)
		}
		if err := os.Setenv(proofHostLockPathEnv, filepath.Join(filepath.Dir(storagePath), ".proof-work.lock")); err != nil {
			log.Fatalf("configure proof host lock: %v", err)
		}
	}

	ctx := context.Background()
	if *mode == "server" || *mode == "proof-daemon" {
		installVKStopSignals()
	}
	if *maxPieceSizeBytes < 0 {
		log.Fatal("--max-piece-size-bytes must be >= 0")
	}
	if *maxConcurrentUploads <= 0 || *maxConcurrentDownloads <= 0 || *maxQueuedTransfers < 0 || *maxTransfersPerPeer <= 0 {
		log.Fatal("transfer concurrency limits must be positive (queue may be zero)")
	}
	if *maxTemporaryUploadBytes < 0 || *transferQueueWaitSeconds < 0 || *transferRetryAfterSeconds <= 0 ||
		*partialUploadTTLSeconds <= 0 || *completedTransferTTLSeconds <= 0 ||
		*quoteReservationQuantumBytes <= 0 || *maxOutstandingQuoteReservations <= 0 ||
		*maxOutstandingQuotesPerIdentity <= 0 || *quoteReservationReconcileSeconds <= 0 ||
		*maxOpenQuotesPerFile <= 0 || *maxUnusedQuotesPerFile <= 0 || *unusedQuoteWindowSeconds <= 0 ||
		*quoteHoldGas < 0 ||
		*quoteTransferMinBytesPerSecond <= 0 || *quoteTransferRecoveryGraceSeconds <= 0 ||
		*filesystemReserveBytes < 0 ||
		*proofTransferReservePercent < 0 || *proofTransferReservePercent >= 100 {
		log.Fatal("invalid transfer resource-limit configuration")
	}
	if err := setChainProofCommandTimeout(time.Duration(*chainCommandTimeoutSeconds) * time.Second); err != nil {
		log.Fatalf("invalid --chain-command-timeout-seconds: %v", err)
	}

	// Derive VK Ethereum address from private key when receipt signing is enabled.
	vkAddr := ""
	if *vkPrivKeyHex != "" {
		if pk, err := ParseVKPrivKey(*vkPrivKeyHex); err != nil {
			log.Fatalf("invalid --vk-private-key: %v", err)
		} else {
			vkAddr = VKAddressFromKey(pk)
			if *chainID != 0 {
				log.Printf("[receipt] signing enabled  vkAddress=%s  chainId=%d", vkAddr, *chainID)
			} else {
				log.Printf("[vk] key loaded  vkAddress=%s", vkAddr)
			}
		}
	}
	if strings.TrimSpace(os.Getenv(proofJobVKIdentityEnv)) == "" {
		identity := strings.TrimSpace(vkAddr)
		if identity == "" {
			storagePath, err := filepath.Abs(*storage)
			if err != nil {
				log.Fatalf("resolve storage path for proof job identity: %v", err)
			}
			identity = "storage:" + storagePath
		}
		if err := os.Setenv(proofJobVKIdentityEnv, identity); err != nil {
			log.Fatalf("configure proof job VK identity: %v", err)
		}
	}

	cfg := ServerConfig{
		Storage:                                 *storage,
		RPCURL:                                  *rpcURL,
		ACLAddress:                              *aclAddress,
		AllowUnauthenticatedReads:               *allowOpenReads,
		AllowUnauthenticatedWrites:              *allowOpenWrites,
		AllowUnverifiedPayments:                 *allowUnverifiedPayments,
		AllowLegacyUnauthenticatedUploads:       *allowLegacyUploads,
		PieceBlockSize:                          *pieceBlockSize,
		MaxPieceSizeBytes:                       *maxPieceSizeBytes,
		MaxConcurrentUploads:                    *maxConcurrentUploads,
		MaxConcurrentDownloads:                  *maxConcurrentDownloads,
		MaxQueuedTransfers:                      *maxQueuedTransfers,
		MaxTransfersPerPeer:                     *maxTransfersPerPeer,
		MaxTemporaryUploadBytes:                 *maxTemporaryUploadBytes,
		TransferQueueWaitSeconds:                *transferQueueWaitSeconds,
		TransferRetryAfterSeconds:               *transferRetryAfterSeconds,
		PartialUploadTTLSeconds:                 *partialUploadTTLSeconds,
		CompletedTransferTTLSeconds:             *completedTransferTTLSeconds,
		QuoteReservationQuantumBytes:            *quoteReservationQuantumBytes,
		MaxOutstandingQuoteReservations:         *maxOutstandingQuoteReservations,
		MaxOutstandingQuotesPerIdentity:         *maxOutstandingQuotesPerIdentity,
		MaxOpenQuotesPerFile:                    *maxOpenQuotesPerFile,
		MaxUnusedQuotesPerFile:                  *maxUnusedQuotesPerFile,
		UnusedQuoteWindowSeconds:                *unusedQuoteWindowSeconds,
		QuoteHoldGas:                            *quoteHoldGas,
		QuoteReservationReconcileSeconds:        *quoteReservationReconcileSeconds,
		QuoteTransferMinBytesPerSecond:          *quoteTransferMinBytesPerSecond,
		QuoteTransferRecoveryGraceSeconds:       *quoteTransferRecoveryGraceSeconds,
		FilesystemReserveBytes:                  *filesystemReserveBytes,
		ProofTransferReservePercent:             *proofTransferReservePercent,
		ProofBackgroundMinWorkers:               *proofBackgroundMinWorkers,
		ProofBackgroundMaxWorkers:               *proofBackgroundMaxWorkers,
		ProofBackgroundBusyCPUPercent:           *proofBackgroundBusyCPUPercent,
		ProofDeadlineConservativeBoundSeconds:   *proofDeadlineConservativeBoundSeconds,
		SectorMaxPieces:                         *sectorMaxPieces,
		SectorLifetimeDays:                      *sectorLifetimeDays,
		AllowSectorExtend:                       *allowSectorExtend,
		ZKBlockSize:                             *zkBlockSize,
		ZKTreeDepth:                             *zkTreeDepth,
		DeadlineCount:                           *deadlineCount,
		PartitionMaxSectors:                     *partitionMaxSectors,
		ProofPeriodSeconds:                      *proofPeriodSeconds,
		ChallengeCount:                          *challengeCount,
		PartitionProverCmd:                      *partitionProverCmd,
		DeterministicChallenge:                  *deterministicChallenge,
		SectorMaxExpirationExtension:            *sectorMaxExpirationExtension,
		SectorAllowLargeMixing:                  *sectorAllowLargeMixing,
		VKPrivKeyHex:                            *vkPrivKeyHex,
		VKAddress:                               vkAddr,
		ChainID:                                 *chainID,
		DeploymentManifestPath:                  *deploymentManifestPath,
		DeployedAddressesPath:                   *deployedAddressesPath,
		StorageProofContract:                    *storageProofContract,
		CapacityProofContract:                   *capacityProofContract,
		FileRegistrationContract:                *fileRegistrationContract,
		DeletionReleaseContract:                 *deletionReleaseContract,
		VKRegistryContract:                      *vkRegistryContract,
		VKRegistryABIPath:                       *vkRegistryABI,
		AdvertiseIP:                             *advertiseIP,
		PublicAddrCheckSeconds:                  *publicAddrCheckSeconds,
		PublicAddrFullCheckSeconds:              *publicAddrFullCheckSeconds,
		PublicAddrMinChangeSeconds:              *publicAddrMinChangeSeconds,
		PublicAddrEchoURLs:                      parseDiscoveryURLs(*publicAddrEchoURLs),
		PublicAddrHelpers:                       *publicAddrHelpers,
		PublicAddrPortMapping:                   *publicAddrPortMapping,
		ReachHelperEnabled:                      *reachHelper,
		StorageFee:                              *storageFee,
		MaxServiceDays:                          uint32(*maxServiceDays),
		SuToWeiRate:                             *suToWeiRate,
		FixedGasPriceWei:                        *fixedGasPriceWei,
		StakeWei:                                *stakeWei,
		VKEscrowContract:                        *vkEscrowContract,
		EscrowAllowUnfinalizedStores:            *escrowAllowUnfinalizedStores,
		DiscoveryURLs:                           parseDiscoveryURLs(*discoveryURLs),
		DiscoveryTTLSeconds:                     *discoveryTTLSeconds,
		DiscoveryHeartbeatSeconds:               *discoveryHeartbeatSeconds,
		TransactionLogPath:                      *transactionLogPath,
		LogMaxMB:                                *logMaxMB,
		LogKeepDays:                             *logKeepDays,
		LogMaxTotalMB:                           *logMaxTotalMB,
		CapacityBytes:                           *capacityBytes,
		CapacitySlotSizeBytes:                   *capacitySlotSizeBytes,
		CapacityProofDebounceSeconds:            *capacityProofDebounceSeconds,
		CapacityProofMaxBatchSeconds:            *capacityProofMaxBatchSeconds,
		CapacityProofMaxPendingMutations:        *capacityProofMaxPendingMutations,
		CapacityProofMaxPendingBytes:            *capacityProofMaxPendingBytes,
		CapacityProofMaxDivergenceBytes:         *capacityProofMaxDivergenceBytes,
		CapacityProofMaxTouchedPartitions:       *capacityProofMaxTouchedPartitions,
		CapacityProofMaxOldestMutationSeconds:   *capacityProofMaxOldestMutationSeconds,
		CapacityProofMaxQueueDepth:              *capacityProofMaxQueueDepth,
		CapacityProofMaxConsecutiveFailedEpochs: *capacityProofMaxConsecutiveFailedEpochs,
		CapacityProofSubmissionSafetySeconds:    *capacityProofSubmissionSafetySeconds,
		ResumeCapacity:                          *resumeCapacity,
		ForceCapacityRebuild:                    *forceCapacityRebuild,
		AdmissionMarginBytes:                    *admissionMarginBytes,
		SyncAdmissionToRegistry:                 *syncAdmissionToRegistry,
		ChainProofCmd:                           *chainProofCmd,
	}
	if err := configureProofResourceController(cfg); err != nil {
		log.Fatalf("invalid proof resource configuration: %v", err)
	}
	if err := validateCapacityProofBatchConfig(cfg); err != nil {
		log.Fatalf("invalid capacity proof batching configuration: %v", err)
	}
	if cfg.ProofTransferReservePercent != 0 {
		log.Printf("[proof-resource] proof_transfer_reserve_percent=%d is deprecated and ignored; foreground transfer limits are never reduced", cfg.ProofTransferReservePercent)
	}
	setTransactionLogPath(cfg.TransactionLogPath)
	// Applied before the mode switch so the server and the proof daemon, which both compute
	// admission, agree on the same cold bound.
	setProofDeadlineConservativeBound(cfg.ProofDeadlineConservativeBoundSeconds)
	_ = partitionProverCmd // consumed by proof-daemon via env/config

	rootArg := *pieceRoot
	if rootArg == "" {
		rootArg = *cid
	}

	switch *mode {
	case "server":
		runServer(ctx, *listen, cfg)
	case "store":
		mustHave(*peerAddr, "--peer")
		mustHave(*filePath, "--file")
		runStore(ctx, *peerAddr, *filePath, *fileID, *pieceIndex, *serviceEnd, *commitmentNonce, *paymentCommitment, *fileFormat, *deletionAuthHash, *transferID, *uploader, *transferIssuedAt, *transferSig, *expectedPieceRoot, *expectedPieceBlockSize)
	case "quote":
		mustHave(*peerAddr, "--peer")
		if *pieceSize <= 0 {
			log.Fatal("missing or invalid --size")
		}
		runQuote(ctx, *peerAddr, *pieceSize, *serviceEnd, *transferID,
			*blockedDemandID, *blockedDemandCapability, *clientIdentityKey,
			*fileID, *uploader, *transferIssuedAt, *transferSig)
	case "renew":
		mustHave(*peerAddr, "--peer")
		mustHave(*paymentCommitment, "--payment-commitment")
		if *serviceEnd <= 0 {
			log.Fatal("missing or invalid --service-end")
		}
		runRenew(ctx, *peerAddr, *paymentCommitment, *serviceEnd, *clientIdentityKey)
	case "info":
		mustHave(*peerAddr, "--peer")
		runInfo(ctx, *peerAddr)
	case "get":
		mustHave(*peerAddr, "--peer")
		mustHave(rootArg, "--piece-root")
		mustHave(*filePath, "--file")
		runGet(ctx, *peerAddr, rootArg, *filePath, *fileID, *requester, *sig, *issuedAt)
	case "prove":
		mustHave(*peerAddr, "--peer")
		mustHave(rootArg, "--piece-root")
		runProve(ctx, *peerAddr, rootArg)
	case "delete":
		mustHave(*peerAddr, "--peer")
		mustHave(*commitmentHash, "--commitment-hash")
		runDelete(ctx, *peerAddr, *commitmentHash, *deletionAuthSecret, *redriveCapable,
			*deleteRequester, *deleteIssuedAt, *deleteSig)
	case "recovery-receipt":
		mustHave(*peerAddr, "--peer")
		mustHave(rootArg, "--piece-root")
		mustHave(*fileID, "--file-id")
		mustHave(*requester, "--requester")
		mustHave(*sig, "--sig")
		runRecoveryReceipt(ctx, *peerAddr, *fileID, rootArg, *requester, *issuedAt, *sig)
	case "recovery-vault":
		mustHave(*peerAddr, "--peer")
		mustHave(*fileID, "--file-id")
		mustHave(*recoveryUploadID, "--recovery-upload-id")
		mustHave(*requester, "--requester")
		mustHave(*sig, "--sig")
		runRecoveryVault(ctx, *peerAddr, *fileID, *recoveryUploadID, *recoverySealed,
			*requester, *issuedAt, *sig)
	case "has-piece":
		mustHave(*peerAddr, "--peer")
		mustHave(rootArg, "--piece-root")
		runHasPiece(ctx, *peerAddr, rootArg)
	case "quiesce-freezes":
		ensureStorageForCLI(*storage)
		if err := runFreezeQuiesceCLI(*storage, vkAddr, *quiesceState); err != nil {
			log.Fatalf("[quiesce] %v", err)
		}
	case "gc":
		if *olderHours <= 0 {
			log.Fatal("missing or invalid --older-hours")
		}
		runGC(*storage, time.Duration(*olderHours)*time.Hour)
	case "expired-gc":
		mustHave(*chainProofCmd, "--chain-proof-cmd")
		ensureStorageForCLI(*storage)
		clock, clockErr := proofClockStatusOnChain(*chainProofCmd)
		if clockErr != nil {
			log.Fatalf("[gc] blockchain time unavailable; refusing unsafe host-time cleanup: %v", clockErr)
		}
		log.Printf("[gc] running one-shot expired-sector cleanup storage=%s chainTimestamp=%d", *storage, clock.ChainTimestamp)
		result := runExpiredGCDetailedAt(*storage, nil, clock.ChainTimestamp)
		reconcileExpiredGCDataPartitions(cfg, clock.ChainTimestamp, nil)
		settleExpiredGCCapacityRecords(cfg, clock.ChainTimestamp, nil)
		log.Printf("[gc] done sectorsRemoved=%d piecesRemoved=%d pendingPartitions=%d failures=%d",
			result.SectorsRemoved, result.PiecesRemoved, len(result.Affected), result.Failures)
	case "sectors":
		ensureStorageForCLI(*storage)
		listSectorsJSON(*storage)
	case "sector-proof":
		mustHave(*sectorID, "--sector-id")
		if *round == 0 {
			*round = currentProofRound(*proofPeriodSeconds)
		}
		if *chainProofCmd != "" {
			ensureStorageForCLI(*storage)
			sector, err := readSector(*storage, *sectorID)
			if err != nil {
				fatalJSON(err)
			}
			if err := proveSectorWithChain(*storage, sector, *round, *challengeCount, *zkProverCmd, *chainProofCmd); err != nil {
				fatalJSON(err)
			}
			writePrettyJSON(os.Stdout, map[string]any{"ok": true, "sectorId": *sectorID, "round": *round})
			return
		}
		runSectorProof(*storage, *sectorID, *round, *challengeCount, *challengeSeed, *zkProverCmd)
	case "proof-daemon":
		mustHave(*zkProverCmd, "--zk-prover-cmd")
		mustHave(*chainProofCmd, "--chain-proof-cmd")
		if cfg.CapacityBytes > 0 {
			mustHave(cfg.CapacityProofContract, "--capacity-proof-contract")
			if !cfg.DeterministicChallenge || cfg.DeadlineCount <= 0 || cfg.PartitionProverCmd == "" {
				log.Fatal("capacity proof daemon requires deterministic partition snapshots")
			}
		}
		runProofDaemon(*storage, *proofPeriodSeconds, *proofPollSeconds, *challengeCount, *zkProverCmd, *chainProofCmd, *proofOnce, *deadlineCount, *partitionMaxSectors, *partitionProverCmd, *deterministicChallenge, cfg.CapacityBytes, cfg)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}

func cidV0FromSHA256(hashBytes []byte) string {
	multihashBytes := append([]byte{0x12, 0x20}, hashBytes...)
	return base58.Encode(multihashBytes)
}

func writeJSON(w io.Writer, v any) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(w, "%s\n", b)
}

func writePrettyJSON(w io.Writer, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(w, string(b))
}

func fatalJSON(err error) {
	writePrettyJSON(os.Stderr, map[string]any{"ok": false, "err": err.Error()})
	os.Exit(1)
}

func mustHave(v, name string) {
	if strings.TrimSpace(v) == "" {
		log.Fatalf("missing %s", name)
	}
}

func sameRoot(a, b string) bool { return strings.EqualFold(normalizeRoot(a), normalizeRoot(b)) }

func sha256Hex(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

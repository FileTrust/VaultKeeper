package main

import (
	"time"

	"github.com/libp2p/go-libp2p/core/protocol"
)

const (
	StoreProtocol    protocol.ID = "/filetrust/store/2.0.0"
	StoreProtocolV3  protocol.ID = "/filetrust/store/3.0.0"
	GetProtocol      protocol.ID = "/filetrust/get/2.0.0"
	ProveProtocol    protocol.ID = "/filetrust/prove/2.0.0"
	QuoteProtocol    protocol.ID = "/filetrust/quote/1.0.0"
	RenewProtocol    protocol.ID = "/filetrust/renew/1.0.0"
	DeleteProtocol   protocol.ID = "/filetrust/delete/1.0.0"
	HasPieceProtocol protocol.ID = "/filetrust/has-piece/1.0.0"
	InfoProtocol     protocol.ID = "/filetrust/info/1.0.0"

	// What a data owner may ask for after losing its own records: the receipt
	// this keeper signed, and the sealed copy it holds on the owner's behalf.
	RecoveryReceiptProtocol protocol.ID = "/filetrust/recovery-receipt/1.0.0"
	RecoveryVaultProtocol   protocol.ID = "/filetrust/recovery-vault/1.0.0"

	HashAlgSha256                                  = "sha2-256"
	RootAlgMerkleSHA256                            = "merkle-sha256-v1"
	RootAlgZKMiMCBN254                             = "mimc-bn254-sector-blocks-v2"
	DefaultZKBlockSize                             = 128
	DefaultZKTreeDepth                             = 28
	DefaultPieceBlockSize                          = 64 * 1024
	DefaultSectorMaxPieces                         = 1024
	DefaultSectorLifetimeDays                      = 30
	DefaultDiscoveryTTLSeconds                     = 8 * 60 * 60
	DefaultDiscoveryHeartbeatSeconds               = 2 * 60 * 60
	DefaultCapacityProofDebounceSeconds            = 30 * 60
	DefaultCapacityProofMaxBatchSeconds            = 30 * 60
	DefaultCapacityProofMaxPendingMutations        = 64
	DefaultCapacityProofMaxPendingBytes            = int64(1024 * 1024 * 1024)
	DefaultCapacityProofMaxDivergenceBytes         = int64(512 * 1024 * 1024)
	DefaultCapacityProofMaxTouchedPartitions       = 16
	DefaultCapacityProofMaxOldestMutationSeconds   = int64(30 * 60)
	DefaultCapacityProofMaxQueueDepth              = 8
	DefaultCapacityProofMaxConsecutiveFailedEpochs = 3
	DefaultCapacityProofSubmissionSafetySeconds    = int64(120)
	DefaultMaxConcurrentUploads                    = 4
	DefaultMaxConcurrentDownloads                  = 8
	DefaultMaxQueuedTransfers                      = 32
	DefaultMaxTransfersPerPeer                     = 4
	DefaultTransferQueueWaitSeconds                = 2
	DefaultTransferRetryAfterSeconds               = 5
	DefaultPartialUploadTTLSeconds                 = 24 * 60 * 60
	DefaultCompletedTransferTTLSeconds             = 7 * 24 * 60 * 60
	// Quote reservations use a coarse allocation unit so the public chain does
	// not reveal the raw private piece size. Waste is bounded to one quantum per
	// live piece and the setting remains explicitly configurable.
	DefaultQuoteReservationQuantumBytes            = 64 * 1024
	DefaultMaxOutstandingQuoteReservations         = 64
	DefaultMaxOutstandingQuotesPerIdentity         = 4
	DefaultQuoteReservationReconcileSeconds  int64 = 15
	DefaultQuoteTransferMinBytesPerSecond    int64 = 64 * 1024
	DefaultQuoteTransferRecoveryGraceSeconds int64 = 10 * 60

	// A real upload places one piece of a file on each keeper, so it needs one
	// quote here; two leaves room for a retry. A quote the data owner never came
	// back for is "unused"; a file that leaves this many unused within the window
	// is refused until the window passes.
	DefaultMaxOpenQuotesPerFile           = 2
	DefaultMaxUnusedQuotesPerFile         = 3
	DefaultUnusedQuoteWindowSeconds int64 = 24 * 60 * 60
	// Two GiB. A keeper that accepts any size lets one quote hold its whole disk.
	DefaultMaxPieceSizeBytes int64 = 2 * 1024 * 1024 * 1024
	// Gas the keeper spends on one quote's hold: CapacityProofSC.reserveQuote
	// (282,351 gas) plus expireQuote (33,123), measured in the contract test
	// suite (Hardhat, solc 0.8.28); the same for every piece size. Rounded up to cover the
	// 20% gas-limit margin the keeper sends with. Charged inside the quoted
	// price, so a data owner who stores pays for the hold it caused.
	DefaultQuoteHoldGas int64 = 400_000
	// ProofTransferReservePercent is retained only so older launch configs keep
	// parsing. Proof work must never reduce foreground transfer concurrency.
	DefaultProofTransferReservePercent = 0
	DefaultProofBackgroundMinWorkers   = 1
	// Zero lets the VK use the process' available CPUs while the host is idle.
	DefaultProofBackgroundMaxWorkers     = 0
	DefaultProofBackgroundBusyCPUPercent = 20
	// DefaultProofDeadlineConservativeBoundSeconds is the cold bound admission assumes for one
	// protected storage-deadline proof before this VK has enough measured history to calibrate
	// down. It stays at the historical 30 minutes so an unset configuration behaves as before.
	DefaultProofDeadlineConservativeBoundSeconds = 1800
	PieceFormatRIDAV1                            = "rida-v1"
	PartitionKindData                            = "data"
	PartitionKindCapacity                        = "capacity"
	CapacityPartitionIndexOffset                 = 128

	// Expiration-bucket defaults.
	// DefaultSectorMaxExpirationExtension is the maximum number of seconds an open
	// sector's expiration may be stretched to accommodate a new piece.
	DefaultSectorMaxExpirationExtension = 7 * 24 * 60 * 60 // 7 days
)

// Automatic public address (advertise-ip auto). Every published change is one
// on-chain endpoint update, so changes are spaced by DefaultPublicAddrMinChangeSeconds.
const (
	DefaultPublicAddrCheckSeconds     int64 = 5 * 60
	DefaultPublicAddrFullCheckSeconds int64 = 60 * 60
	DefaultPublicAddrMinChangeSeconds int64 = 10 * 60
	DefaultPublicAddrHelpers                = 3
)

// DefaultPublicAddrEchoURLs are "what is my IP" services run by different
// companies (ipify, Amazon, Cloudflare, ifconfig.me, ipinfo). Each is one vote;
// none decides alone.
var DefaultPublicAddrEchoURLs = []string{
	"https://api.ipify.org",
	"https://checkip.amazonaws.com",
	"https://icanhazip.com",
	"https://ifconfig.me/ip",
	"https://ipinfo.io/ip",
}

// DefaultSectorExpirationBuckets are the built-in bucket thresholds (seconds
// from now) used when no buckets are configured: 30 / 90 / 180 / 365 days.
var DefaultSectorExpirationBuckets = []int64{
	30 * 24 * 3600,  // 30 days
	90 * 24 * 3600,  // 90 days
	180 * 24 * 3600, // 180 days
	365 * 24 * 3600, // 365 days
}

type ServerConfig struct {
	Storage    string
	RPCURL     string
	ACLAddress string
	// Serve pieces to anyone, with no access-control check at all. Only
	// sensible on a closed test network, and it has to be asked for: leaving
	// the ACL unconfigured must not be a way to arrive here by accident.
	AllowUnauthenticatedReads bool
	// Accept uploads without confirming on chain that the uploader owns the
	// file. Same reasoning as the read switch: only for a closed test network,
	// and never something a missing flag arrives at on its own.
	AllowUnauthenticatedWrites bool
	// Store pieces without confirming on chain that they were paid for. A
	// separate switch from the one above on purpose: waiving the ownership
	// check is not the same decision as agreeing to give storage away, and one
	// flag covering both would let an operator make the second choice by
	// accident while intending the first.
	AllowUnverifiedPayments bool
	// Serve the v2 upload protocol, which performs no authorization at all.
	AllowLegacyUnauthenticatedUploads bool
	PieceBlockSize                    int64
	MaxPieceSizeBytes                 int64
	MaxConcurrentUploads              int
	MaxConcurrentDownloads            int
	MaxQueuedTransfers                int
	MaxTransfersPerPeer               int
	MaxTemporaryUploadBytes           int64
	TransferQueueWaitSeconds          int64
	TransferRetryAfterSeconds         int64
	PartialUploadTTLSeconds           int64
	CompletedTransferTTLSeconds       int64
	QuoteReservationQuantumBytes      int64
	MaxOutstandingQuoteReservations   int
	MaxOutstandingQuotesPerIdentity   int
	MaxOpenQuotesPerFile              int
	MaxUnusedQuotesPerFile            int
	UnusedQuoteWindowSeconds          int64
	QuoteHoldGas                      int64
	QuoteReservationReconcileSeconds  int64
	QuoteTransferMinBytesPerSecond    int64
	QuoteTransferRecoveryGraceSeconds int64
	// FilesystemReserveBytes is hard operational headroom outside advertised
	// sellable capacity. Zero derives a safe reserve from proof/upload workspace.
	FilesystemReserveBytes int64
	// Deprecated: accepted for configuration compatibility, but intentionally
	// ignored. Background proof preparation yields to foreground operations.
	ProofTransferReservePercent   int
	ProofBackgroundMinWorkers     int
	ProofBackgroundMaxWorkers     int
	ProofBackgroundBusyCPUPercent int
	// ProofDeadlineConservativeBoundSeconds overrides the cold storage-deadline proof bound.
	// Zero or negative keeps DefaultProofDeadlineConservativeBoundSeconds.
	ProofDeadlineConservativeBoundSeconds int
	SectorMaxPieces                       int
	SectorLifetimeDays                    int
	AllowSectorExtend                     bool
	ZKBlockSize                           int64
	ZKTreeDepth                           int
	DeadlineCount                         int
	PartitionMaxSectors                   int
	ProofPeriodSeconds                    int64
	ChallengeCount                        int
	PartitionProverCmd                    string
	// DeterministicChallenge skips openPartitionChallenge and uses a single
	// submitPartitionZkProofDeterministic tx instead of the legacy two-tx path.
	DeterministicChallenge bool

	// Expiration-bucket placement policy.
	// SectorExpirationBuckets is a sorted list of bucket durations in seconds from now.
	// Pieces are placed into sectors whose expiration bucket best matches serviceEnd.
	// Defaults to DefaultSectorExpirationBuckets when empty.
	SectorExpirationBuckets []int64
	// SectorMaxExpirationExtension is the maximum number of seconds an existing
	// open sector may be extended to accommodate a piece. 0 = use default (7 days).
	SectorMaxExpirationExtension int64
	// SectorAllowLargeMixing controls whether pieces may be placed in sectors
	// whose expiration bucket is more than one bucket larger than the piece needs.
	// false = strict (default); true = allow any bucket mismatch.
	SectorAllowLargeMixing bool

	// Private receipt signing.
	// VKPrivKeyHex is the hex-encoded Ethereum private key used to sign storage receipts.
	// When non-empty the VK signs and returns a PrivateReceiptV1 on every store.
	VKPrivKeyHex string
	// VKAddress is the Ethereum address derived from VKPrivKeyHex (set at startup).
	VKAddress string
	// ChainID is the EVM chain id, used in receipt fields and signature domain separation.
	ChainID int64
	// DeploymentManifestPath, when set, points at the versioned deployment manifest the
	// VK verifies at startup (chain id + addresses + runtime code hashes + ABI + wiring).
	DeploymentManifestPath string
	// DeployedAddressesPath, when set, is hashed and its addresses cross-checked against
	// the manifest's deployedAddressesHash at startup.
	DeployedAddressesPath string
	// StorageProofContract is the StorageProofSC address written into receipts so DO
	// can confirm which contract to dispute against.
	StorageProofContract string
	// CapacityProofContract owns authoritative blinded quote reservations and
	// conservative capacity accounting.
	CapacityProofContract string
	// FileRegistrationContract is the FileRegistrationSC address. When non-empty,
	// VK calls registerFileStorage() on-chain after each successful store.
	FileRegistrationContract string
	// DeletionReleaseContract is the G.4 deletion-scoped lineage and receipt authority.
	DeletionReleaseContract string

	// VaultKeeper self-registration.
	// When VKRegistryContract and VKRegistryABIPath are set, the VK sends
	// registerVaultKeeper (or updateVaultKeeper) on startup using its own private key.
	VKRegistryContract string
	VKRegistryABIPath  string
	AdvertiseIP        string
	StorageFee         int64  // SU per GB per day — must match VaultKeeperRegistry.storageFee
	MaxServiceDays     uint32 // max service duration VK accepts (days); 0 = unlimited
	SuToWeiRate        int64  // Wei per SU — shared protocol constant, matches RewardManager.suToWeiRate
	FixedGasPriceWei   int64  // Wei gas price used for local FileTrust transactions
	StakeWei           string // decimal string, e.g. "0" or "1000000000000000"
	VKEscrowContract   string // VKEscrow contract address; used to verify DO deposits before accepting files
	// EscrowAllowUnfinalizedStores permits accepting bond-first (not-yet-finalized)
	// escrow deposits in hybrid mode as long as escrow exists and terms match.
	EscrowAllowUnfinalizedStores bool

	// FileTrust VK discovery.
	// Discovery records are signed peerId -> multiaddr reachability records.
	DiscoveryURLs             []string
	DiscoveryTTLSeconds       int64
	DiscoveryHeartbeatSeconds int64
	TransactionLogPath        string

	// Log housekeeping, from config.json. Zero means use the defaults in
	// log_archive.go (50 MB / 14 days / 1 GB).
	LogMaxMB      int64
	LogKeepDays   int
	LogMaxTotalMB int64

	// CapacityBytes is the total storage capacity this VK claims, backed by
	// committed capacity sectors filled with deterministic dummy data.
	// 0 = no capacity commitment. Set via --capacity-bytes.
	CapacityBytes int64

	// CapacitySlotSizeBytes bounds each committed free-capacity sector. Zero uses
	// the automatic fixed-slot plan (about 128 slots, at least 64 MiB each, and
	// never larger than the configured ZK sector circuit).
	CapacitySlotSizeBytes int64

	// Capacity proof service objectives. Byte limits are absolute so operators
	// can calibrate profiles from measured circuit/prover throughput for VKs from
	// test scale through multi-terabyte deployments.
	CapacityProofDebounceSeconds            int64
	CapacityProofMaxBatchSeconds            int64
	CapacityProofMaxPendingMutations        int
	CapacityProofMaxPendingBytes            int64
	CapacityProofMaxDivergenceBytes         int64
	CapacityProofMaxTouchedPartitions       int
	CapacityProofMaxOldestMutationSeconds   int64
	CapacityProofMaxQueueDepth              int
	CapacityProofMaxConsecutiveFailedEpochs int
	CapacityProofSubmissionSafetySeconds    int64

	// ResumeCapacity enables fast restart after crash: verify existing capacity
	// sector + ZK cache integrity before rebuilding dummy free-space data.
	ResumeCapacity bool

	// ForceCapacityRebuild skips integrity reuse and always rebuilds capacity
	// sectors and ZK caches from scratch.
	ForceCapacityRebuild bool

	// AdmissionMarginBytes is subtracted from fresh certified free capacity after
	// live durable reservations. A new request must fit in the remainder.
	// 0 uses 100 MiB.
	AdmissionMarginBytes int64

	// SyncAdmissionToRegistry publishes admission open/closed to VaultKeeperRegistry.
	SyncAdmissionToRegistry bool

	// ChainProofCmd is the chain command used to submit on-chain transactions.
	// When set, the VK declares capacity on startup and updates usage periodically.
	ChainProofCmd string

	// Automatic public address (AdvertiseIP "auto"); see public_address.go.
	PublicAddrCheckSeconds     int64
	PublicAddrFullCheckSeconds int64
	PublicAddrMinChangeSeconds int64
	PublicAddrEchoURLs         []string
	PublicAddrHelpers          int
	PublicAddrPortMapping      bool
	// ReachHelperEnabled answers other keepers' call-back requests.
	ReachHelperEnabled bool
	// PublicAddrAllowPrivate lets tests on one machine use private and loopback
	// addresses. No flag sets it: on the internet a private address is never a
	// public one, and a helper must never be pointed at one.
	PublicAddrAllowPrivate bool
}

// PrivateReceiptV1 is a VK-signed private commitment that a piece was stored in a
// specific sector which belongs to a specific deadline/partition.
// It is returned to DO after a successful store and kept locally; it never appears
// on-chain in normal operation. Only submitted to StorageReceiptDispute during a
// dispute.
//
// Signing digest:  keccak256(abi.encodePacked(all fields except VKSignature,
//
//	CommitmentHash, CommitmentNonce))
//
// Signature:       Ethereum personal_sign (EIP-191) over the 32-byte digest.
//
// CommitmentHash and CommitmentNonce are informational fields added alongside the
// existing signature; they are not part of the signed digest in V1 so that
// StorageReceiptDispute.sol remains compatible without changes.
type PrivateReceiptV1 struct {
	ReceiptVersion       int    `json:"receiptVersion"`
	ReceiptNonce         string `json:"receiptNonce"`
	VKAddress            string `json:"vkAddress"`
	PieceRoot            string `json:"pieceRoot"`
	PieceSize            int64  `json:"pieceSize"`
	SectorID             string `json:"sectorId"`
	SectorRoot           string `json:"sectorRoot"`
	DeadlineIndex        int    `json:"deadlineIndex"`
	PartitionIndex       int    `json:"partitionIndex"`
	PartitionRoot        string `json:"partitionRoot"`
	ServiceEnd           int64  `json:"serviceEnd"`
	Timestamp            int64  `json:"timestamp"`
	ChainID              int64  `json:"chainId"`
	StorageProofContract string `json:"storageProofContract"`
	VKSignature          string `json:"vkSignature"`
	// CommitmentHash = keccak256(abi.encodePacked(pieceRoot, commitmentNonce)).
	// Registered on FileRegistrationSC so DO can verify the on-chain record.
	// Never stored on-chain as part of normal receipt flow.
	CommitmentHash string `json:"commitmentHash,omitempty"`
	// CommitmentNonce echoed back to DO so it can recompute commitmentHash locally.
	CommitmentNonce string `json:"commitmentNonce,omitempty"`
	// RegistrationTxHash is the transaction hash of the FileRegistrationSC
	// registerFileStorage() call. Empty when FileRegistrationContract is not
	// configured, or when the record already existed (idempotent retry).
	// DO uses this to independently confirm on-chain registration was mined.
	RegistrationTxHash string `json:"registrationTxHash,omitempty"`
	// DeletionAuthHash = keccak256(deletionAuthSecret), chosen by DO and
	// registered on FileRegistrationSC V2. VK only learns the secret if DO later
	// requests early deletion.
	DeletionAuthHash string `json:"deletionAuthHash,omitempty"`

	// ── Payment commitment fields (VKEscrow) ─────────────────────────────────
	// PaymentCommitment = keccak256(abi.encodePacked(nullifier, secret)).
	// DO deposits this into VKEscrow.depositEscrow() with the agreed amount.
	// VK keeps (nullifier, secret) private and claims via VKEscrow.claimEscrow().
	PaymentCommitment string `json:"paymentCommitment,omitempty"`
	// SizeCommitment = keccak256(abi.encodePacked(uint64(pieceSize), bytes32(sizeNonce))).
	// Stored in VKEscrow alongside the escrow so DO can later dispute claimed size.
	SizeCommitment string `json:"sizeCommitment,omitempty"`
	// SizeNonce is the random 32-byte value used to build SizeCommitment.
	// DO uses (PieceSize, SizeNonce) to verify SizeCommitment locally before depositing.
	SizeNonce string `json:"sizeNonce,omitempty"`
	// AgreedPriceWei is the total escrow amount VK expects: storageFee * size * duration.
	// Informational only — DO verifies against VaultKeeperRegistry.storageFee before paying.
	AgreedPriceWei string `json:"agreedPriceWei,omitempty"`

	// ── Registration linkage (VKEscrow ↔ FileRegistrationSC privacy bridge) ───
	// RegistrationCommitment = keccak256(regNullifier || regSecret).
	// VK registers this on FileRegistrationSC so VKEscrow.claimEscrow() can verify
	// VK actually stored the file. Kept private until VK claims.
	RegistrationCommitment string `json:"registrationCommitment,omitempty"`
	// LinkCommitment = keccak256(paymentCommitment || registrationCommitment || linkNonce).
	// DO includes this in depositEscrow(). Observers cannot link paymentCommitment to
	// registrationCommitment without linkNonce, which only the VK and the data owner
	// (from the quote) know until a claim, refund or settlement publishes it.
	LinkCommitment string `json:"linkCommitment,omitempty"`
}

// PaymentCredentials holds the VK-private payment secrets for a stored piece.
// Saved locally by VK at {storage}/payment/{safeID(commitmentHash)}.json.
// Never sent to DO or stored on-chain.
type PaymentCredentials struct {
	CommitmentHash        string `json:"commitmentHash"`
	CommitmentNonce       string `json:"commitmentNonce,omitempty"` // used to verify: keccak256(pieceRoot||nonce)==commitmentHash
	PieceRoot             string `json:"pieceRoot,omitempty"`       // stored to allow deletion flow to locate piece
	PaymentCommitment     string `json:"paymentCommitment"`
	Nullifier             string `json:"nullifier"`
	Secret                string `json:"secret"`
	SizeCommitment        string `json:"sizeCommitment"`
	SizeNonce             string `json:"sizeNonce"`
	PieceSize             int64  `json:"pieceSize"`
	ServiceEnd            int64  `json:"serviceEnd"`
	RegistrationDeadline  int64  `json:"registrationDeadline,omitempty"`
	QuoteValidUntil       int64  `json:"quoteValidUntil,omitempty"`
	ReservationExpiresAt  int64  `json:"reservationExpiresAt,omitempty"`
	ReservedCapacityBytes int64  `json:"reservedCapacityBytes,omitempty"`
	TransferDeadline      int64  `json:"transferDeadline,omitempty"`
	AgreedPriceWei        string `json:"agreedPriceWei"`
	// Registration linkage secrets — used by claimEscrow() and registerFileStorage().
	RegNullifier           string `json:"regNullifier"`
	RegSecret              string `json:"regSecret"`
	RegistrationCommitment string `json:"registrationCommitment"`
	LinkNonce              string `json:"linkNonce"`
	LinkCommitment         string `json:"linkCommitment"`
	DeletionAuthHash       string `json:"deletionAuthHash,omitempty"`
	CreatedAt              string `json:"createdAt"`

	// ─── Renewal (service extension) ──────────────────────────────────────────
	// Set when this VK has quoted an extension for the piece. The preimage is
	// the VK's proof of consent: opening it on-chain confirms the longer term
	// without ever naming the VK, so the DO-VK pair stays hidden.
	ExtNullifier        string `json:"extNullifier,omitempty"`
	ExtSecret           string `json:"extSecret,omitempty"`
	ExtensionCommitment string `json:"extensionCommitment,omitempty"`
	// PendingServiceEnd is the term the VK quoted and is willing to serve.
	PendingServiceEnd int64 `json:"pendingServiceEnd,omitempty"`
	// ExtensionConfirmBy bounds how long the DO's money may sit parked.
	ExtensionConfirmBy int64  `json:"extensionConfirmBy,omitempty"`
	ExtensionPriceWei  string `json:"extensionPriceWei,omitempty"`
	ExtensionQuotedAt  string `json:"extensionQuotedAt,omitempty"`
}

// RenewReq asks the VK to quote a longer service term for a piece it already
// stores. The piece is named by paymentCommitment, which the DO already knows
// and which reveals nothing on its own.
type RenewReq struct {
	PaymentCommitment string `json:"paymentCommitment"`
	NewServiceEnd     int64  `json:"newServiceEnd"`
}

// RenewResp carries the VK's signed consent to serve the longer term. The DO
// passes ExtensionCommitment to VKEscrow.extendEscrow; only the VK can open it.
type RenewResp struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`

	PaymentCommitment   string `json:"paymentCommitment,omitempty"`
	ExtensionCommitment string `json:"extensionCommitment,omitempty"`
	CurrentServiceEnd   int64  `json:"currentServiceEnd,omitempty"`
	NewServiceEnd       int64  `json:"newServiceEnd,omitempty"`
	AddedPriceWei       string `json:"addedPriceWei,omitempty"`
	ConfirmBy           int64  `json:"confirmBy,omitempty"`
	QuoteValidUntil     int64  `json:"quoteValidUntil,omitempty"`
	VKEscrowContract    string `json:"vkEscrowContract,omitempty"`
	VKAddress           string `json:"vkAddress,omitempty"`
	VKSignature         string `json:"vkSignature,omitempty"`
}

type DeleteReq struct {
	CommitmentHash     string `json:"commitmentHash"`
	DeletionAuthSecret string `json:"deletionAuthSecret,omitempty"`
	// RedriveCapable indicates the client (DO) implements the F.1 durable secret-bearing
	// re-drive loop, i.e. it will re-send this request while the VK reports
	// accepted_queued/declared=false. An old client omits it (false); the VK then refuses
	// to durably queue a non-immediately-declarable deletion for that client rather than
	// create an accepted_queued operation the old client can never re-drive.
	RedriveCapable bool `json:"redriveCapable,omitempty"`
	// Who is asking, and their proof of it. The deletion secret is a capability:
	// it shows the sender holds something, not who they are, and it never
	// expires. These bind the request to an identity the chain can check and to
	// a moment in time, so a leaked secret alone no longer destroys the data.
	Requester string `json:"requester,omitempty"`
	IssuedAt  int64  `json:"issuedAt,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type DeleteResp struct {
	OK       bool `json:"ok"`
	Accepted bool `json:"accepted,omitempty"`
	// Declared reports whether the deletion obligation is present on-chain. It is
	// false while the operation is accepted_queued (durably accepted but awaiting
	// FIFO ownership before it can declare). The DO must not treat the deletion as
	// declared until this is true.
	Declared bool `json:"declared,omitempty"`
	// Retryable signals the DO's durable monitor to re-send this secret-bearing
	// request while Declared is false (an accepted_queued deletion can only be
	// declared when it becomes the durable FIFO owner of its partition and a
	// secret-bearing request arrives).
	Retryable bool `json:"retryable,omitempty"`
	// Terminal marks an EXPLICIT permanent rejection (e.g. invalid authorization
	// secret, unknown commitment, missing commitment). Only a terminal response may
	// stop the DO's re-drive as a permanent failure; a generic/unknown error must not.
	Terminal bool `json:"terminal,omitempty"`
	// ErrorCode is a stable machine-readable code for a terminal rejection, e.g.
	// "deletion_redrive_required" when a non-F.1-capable client is refused.
	ErrorCode         string `json:"errorCode,omitempty"`
	DeletionID        string `json:"deletionId,omitempty"`
	Pending           bool   `json:"pending,omitempty"`
	Phase             string `json:"phase,omitempty"`
	Error             string `json:"error,omitempty"`
	Busy              bool   `json:"busy,omitempty"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds,omitempty"`
	RegisterTx        string `json:"registerTx,omitempty"`
	PartitionTx       string `json:"partitionTx,omitempty"`
	ProofTx           string `json:"proofTx,omitempty"`
	ConfirmTx         string `json:"confirmTx,omitempty"`
	ClaimTx           string `json:"claimTx,omitempty"`
}

// HasPieceReq asks the VK whether it still holds a specific piece.
type HasPieceReq struct {
	PieceRoot string `json:"pieceRoot"`
}

// HasPieceResp lets REQ skip VKs that no longer hold a piece.
// When Deleted=true, CommitmentHash and CommitmentNonce are returned so REQ can
// verify on-chain: keccak256(pieceRoot || nonce) == commitmentHash, then call
// FileRegistrationSC.isDeletionConfirmed(commitmentHash).
type HasPieceResp struct {
	Has             bool   `json:"has"`
	Deleted         bool   `json:"deleted"`
	DeletionPending bool   `json:"deletionPending,omitempty"`
	CommitmentHash  string `json:"commitmentHash,omitempty"`
	CommitmentNonce string `json:"commitmentNonce,omitempty"`
	Error           string `json:"error,omitempty"`
}

type StoreReq struct {
	FileID     string `json:"fileId,omitempty"`
	Name       string `json:"name"`
	PieceIndex int    `json:"pieceIndex,omitempty"`
	Size       int64  `json:"size"`
	Offset     int64  `json:"offset,omitempty"`
	Resume     bool   `json:"resume,omitempty"`
	Probe      bool   `json:"probe,omitempty"`
	ServiceEnd int64  `json:"serviceEnd,omitempty"`
	// CommitmentNonce is a 0x-prefixed 32-byte random hex value generated by DO
	// before calling the VK. VK uses it to compute:
	//   commitmentHash = keccak256(pieceRoot || commitmentNonce)
	// and registers commitmentHash on FileRegistrationSC. If empty, VK generates one.
	CommitmentNonce string `json:"commitmentNonce,omitempty"`
	// PaymentCommitment links this store to a pre-issued quote.
	// When set, VK looks up the pre-generated credentials and verifies the escrow
	// deposit on-chain before accepting the file transfer.
	PaymentCommitment string `json:"paymentCommitment,omitempty"`
	// DeletionAuthHash is a DO-chosen hash registered on-chain. The DO keeps the
	// secret and reveals it only when requesting early deletion.
	DeletionAuthHash string `json:"deletionAuthHash,omitempty"`
	// FileFormat is an optional hint from DO about the file format (e.g. "zip").
	// VK stores it in PieceMeta and echoes it back in StoreResp.
	FileFormat string `json:"fileFormat,omitempty"`
	// TransferID is a stable, client-generated identifier used to bind resumable
	// bytes and lifecycle credentials across process and machine restarts.
	TransferID string `json:"transferId,omitempty"`
	// Uploader authorization binds the transfer metadata to the FileTrust data
	// owner. The signature may be refreshed on resume; the signed identity and
	// immutable transfer fields must remain unchanged.
	Uploader          string `json:"uploader,omitempty"`
	TransferIssuedAt  int64  `json:"transferIssuedAt,omitempty"`
	TransferSignature string `json:"transferSignature,omitempty"`
	// ExpectedPieceRoot is computed by the DO before upload and covered by the
	// uploader signature. The VK must compute the same merkle-sha256-v1 root
	// before it may place or register the piece.
	ExpectedPieceRoot      string `json:"expectedPieceRoot,omitempty"`
	ExpectedPieceBlockSize int64  `json:"expectedPieceBlockSize,omitempty"`
}

// QuoteReq is sent by DO to obtain payment commitments BEFORE depositing escrow or
// sending the file. This enables the DO-deposits-first flow.
type QuoteReq struct {
	Size       int64 `json:"size"`
	ServiceEnd int64 `json:"serviceEnd"`
	// TransferID is a random durable identifier. It lets a retry recover the
	// same quote without publishing a DO, file, requester, or piece-root link.
	TransferID string `json:"transferId,omitempty"`
	// CommitmentNonce is optional — DO may provide it now so VK pre-computes commitmentHash.
	CommitmentNonce string `json:"commitmentNonce,omitempty"`
	// BlockedDemandID and BlockedDemandCapability are returned only on a private
	// certified-capacity refusal. Supplying both performs an authenticated normal G.5 retry.
	BlockedDemandID         string `json:"blockedDemandId,omitempty"`
	BlockedDemandCapability string `json:"blockedDemandCapability,omitempty"`
	// The data owner's signed proof that this quote is for a real file it owns,
	// whose key generation is finished. Checked on chain before anything is held.
	// See vaultmeshQuoteAuthMessage for exactly what is signed.
	FileID    string `json:"fileId,omitempty"`
	Uploader  string `json:"uploader,omitempty"`
	IssuedAt  int64  `json:"issuedAt,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// QuoteResp is returned by VK containing all commitment values DO needs to deposit escrow.
type QuoteResp struct {
	OK                      bool   `json:"ok"`
	Err                     string `json:"err,omitempty"`
	Busy                    bool   `json:"busy,omitempty"`
	RetryAfterSeconds       int64  `json:"retryAfterSeconds,omitempty"`
	BlockedDemandID         string `json:"blockedDemandId,omitempty"`
	BlockedDemandCapability string `json:"blockedDemandCapability,omitempty"`
	BlockedDemandState      string `json:"blockedDemandState,omitempty"`
	BlockedDemandExpiresAt  int64  `json:"blockedDemandExpiresAt,omitempty"`
	PaymentCommitment       string `json:"paymentCommitment"`
	SizeCommitment          string `json:"sizeCommitment"`
	LinkCommitment          string `json:"linkCommitment"`
	// LinkNonce opens LinkCommitment to RegistrationCommitment. The data owner
	// keeps it: the admission dispute, the registration timeout and the
	// settlement of a valid storage dispute refund an escrow only with it.
	LinkNonce              string `json:"linkNonce,omitempty"`
	RegistrationCommitment string `json:"registrationCommitment"`
	AgreedPriceWei         string `json:"agreedPriceWei"`
	ServiceEnd             int64  `json:"serviceEnd"`
	VKEscrowContract       string `json:"vkEscrowContract"`
	// QuoteValidUntil bounds how long the DO may deposit escrow against this
	// economic commitment. VKSignature binds the VK, escrow contract, chain,
	// commitments, price, service end, and this deadline.
	QuoteValidUntil       int64  `json:"quoteValidUntil"`
	VKSignature           string `json:"vkSignature"`
	TransferID            string `json:"transferId,omitempty"`
	CapacityProofContract string `json:"capacityProofContract,omitempty"`
	ReservedCapacityBytes int64  `json:"reservedCapacityBytes,omitempty"`
	ReservationExpiresAt  int64  `json:"reservationExpiresAt,omitempty"`
	ReservationTxHash     string `json:"reservationTxHash,omitempty"`
	TransferDeadline      int64  `json:"transferDeadline,omitempty"`
	QuoteVersion          int    `json:"quoteVersion,omitempty"`
	// QuoteSettledState names the outcome when a reused transferId's reservation
	// has already finished, so a caller can tell "the piece is stored" from "the
	// obligation lapsed without storing anything" without parsing the message.
	QuoteSettledState string `json:"quoteSettledState,omitempty"`
}

type StoreResp struct {
	OK                bool              `json:"ok"`
	Err               string            `json:"err,omitempty"`
	Ready             bool              `json:"ready,omitempty"`
	Busy              bool              `json:"busy,omitempty"`
	RetryAfterSeconds int64             `json:"retryAfterSeconds,omitempty"`
	TransferID        string            `json:"transferId,omitempty"`
	ResumeOffset      int64             `json:"resumeOffset,omitempty"`
	Complete          bool              `json:"complete,omitempty"`
	Name              string            `json:"name,omitempty"`
	Size              int64             `json:"size,omitempty"`
	PieceRoot         string            `json:"pieceRoot,omitempty"`
	PieceID           string            `json:"pieceId,omitempty"`
	CID               string            `json:"cid,omitempty"`
	PieceHash         string            `json:"pieceHash,omitempty"`
	HashAlg           string            `json:"hashAlg,omitempty"`
	RootAlg           string            `json:"rootAlg,omitempty"`
	PieceBlockSize    int64             `json:"pieceBlockSize,omitempty"`
	PieceBlockCount   int64             `json:"pieceBlockCount,omitempty"`
	SectorID          string            `json:"sectorId,omitempty"`
	SectorRoot        string            `json:"sectorRoot,omitempty"`
	SectorExpiration  int64             `json:"sectorExpiration,omitempty"`
	PiecePosition     int               `json:"piecePosition,omitempty"`
	InclusionProof    []string          `json:"inclusionProof,omitempty"`
	StoredAt          string            `json:"storedAt,omitempty"`
	FileFormat        string            `json:"fileFormat,omitempty"`
	PrivateReceipt    *PrivateReceiptV1 `json:"privateReceipt,omitempty"`
	// AdmissionFailureSignature is present only when the VK itself rejects a
	// quote-linked store for authoritative capacity reasons.
	AdmissionFailureSignature string `json:"admissionFailureSignature,omitempty"`
}

type GetReq struct {
	PieceRoot string `json:"pieceRoot,omitempty"`
	PieceID   string `json:"pieceId,omitempty"`
	CID       string `json:"cid,omitempty"`
	Offset    int64  `json:"offset,omitempty"`
	FileID    string `json:"fileId,omitempty"`
	Requester string `json:"requester,omitempty"`
	IssuedAt  int64  `json:"issuedAt,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type GetResp struct {
	OK                bool   `json:"ok"`
	Err               string `json:"err,omitempty"`
	Busy              bool   `json:"busy,omitempty"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds,omitempty"`
	Size              int64  `json:"size,omitempty"`
	TotalSize         int64  `json:"totalSize,omitempty"`
	Offset            int64  `json:"offset,omitempty"`
	PieceRoot         string `json:"pieceRoot,omitempty"`
	RootAlg           string `json:"rootAlg,omitempty"`
	PieceBlockSize    int64  `json:"pieceBlockSize,omitempty"`
	FileFormat        string `json:"fileFormat,omitempty"`
}

type ProveReq struct {
	PieceRoot string `json:"pieceRoot,omitempty"`
	PieceID   string `json:"pieceId,omitempty"`
	CID       string `json:"cid,omitempty"`
}

type ProveResp struct {
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
	// Shed rather than refused: the keeper is at its concurrency limit and this
	// request should be retried, not abandoned.
	Busy              bool   `json:"busy,omitempty"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds,omitempty"`
	Exists            bool   `json:"exists"`
	PieceRoot         string `json:"pieceRoot,omitempty"`
	PieceID           string `json:"pieceId,omitempty"`
	PieceHash         string `json:"pieceHash,omitempty"`
	HashAlg           string `json:"hashAlg,omitempty"`
	RootAlg           string `json:"rootAlg,omitempty"`
	PieceBlockSize    int64  `json:"pieceBlockSize,omitempty"`
	PieceBlockCount   int64  `json:"pieceBlockCount,omitempty"`
	Size              int64  `json:"size,omitempty"`
	SectorID          string `json:"sectorId,omitempty"`
	SectorRoot        string `json:"sectorRoot,omitempty"`
	PiecePosition     int    `json:"piecePosition,omitempty"`
}

type PieceMeta struct {
	FileID          string `json:"fileId,omitempty"`
	TransferID      string `json:"transferId,omitempty"`
	Uploader        string `json:"uploader,omitempty"`
	Name            string `json:"name"`
	PieceIndex      int    `json:"pieceIndex,omitempty"`
	PieceRoot       string `json:"pieceRoot"`
	PieceID         string `json:"pieceId"`
	CID             string `json:"cid,omitempty"`
	PieceHash       string `json:"pieceHash"`
	HashAlg         string `json:"hashAlg"`
	RootAlg         string `json:"rootAlg"`
	PieceBlockSize  int64  `json:"pieceBlockSize"`
	PieceBlockCount int64  `json:"pieceBlockCount"`
	Size            int64  `json:"size"`
	ServiceEnd      int64  `json:"serviceEnd,omitempty"`
	SectorID        string `json:"sectorId,omitempty"`
	SectorRoot      string `json:"sectorRoot,omitempty"`
	PiecePosition   int    `json:"piecePosition,omitempty"`
	StoredAt        string `json:"storedAt"`
	FileFormat      string `json:"fileFormat,omitempty"`
}

type SectorMeta struct {
	SectorID            string   `json:"sectorId"`
	SectorRoot          string   `json:"sectorRoot"`
	RootAlg             string   `json:"rootAlg"`
	PieceRoots          []string `json:"pieceRoots"`
	SectorBlockCount    int      `json:"sectorBlockCount"`
	ZKBlockSize         int64    `json:"zkBlockSize"`
	ZKTreeDepth         int      `json:"zkTreeDepth"`
	SectorMaxPieces     int      `json:"sectorMaxPieces"`
	Expiration          int64    `json:"expiration"`
	CreatedAt           string   `json:"createdAt"`
	UpdatedAt           string   `json:"updatedAt"`
	Status              string   `json:"status"`
	LastProofRound      uint64   `json:"lastProofRound,omitempty"`
	LastProofAt         string   `json:"lastProofAt,omitempty"`
	DeadlineIndex       int      `json:"deadlineIndex,omitempty"`
	PartitionIndex      int      `json:"partitionIndex,omitempty"`
	PartitionAssigned   bool     `json:"partitionAssigned,omitempty"`
	PartitionAssignedAt string   `json:"partitionAssignedAt,omitempty"`
	// ZKPieceCommitment is MiMC("FT-COMMIT-V2", pieceRoot_1_hi, pieceRoot_1_lo, ...) for all
	// pieces in this sector. Set when sectorRoot is computed (W3 fix).
	ZKPieceCommitment string `json:"zkPieceCommitment,omitempty"`

	// Expiration-bucket fields (set on sector creation; -1 = legacy/pre-bucket).
	ExpirationBucket int   `json:"expirationBucket"`        // bucket index (never omit so 0 is explicit)
	MinServiceEnd    int64 `json:"minServiceEnd,omitempty"` // earliest piece serviceEnd
	MaxServiceEnd    int64 `json:"maxServiceEnd,omitempty"` // latest piece serviceEnd

	// IsCapacity marks this sector as a committed-capacity sector containing
	// persistent cryptographically random filler rather than real user pieces.
	// Capacity sectors are proven identically to real sectors but are skipped
	// when selecting a sector for an incoming real piece.
	IsCapacity bool `json:"isCapacity,omitempty"`

	// CapacitySlotIndex/CapacitySlotSizeBytes identify a stable free-capacity
	// slot. They are metadata only; the proof still binds to sectorRoot and
	// partition content hash.
	CapacitySlotIndex     int   `json:"capacitySlotIndex,omitempty"`
	CapacitySlotSizeBytes int64 `json:"capacitySlotSizeBytes,omitempty"`
}

// PartitionMeta describes a group of sectors assigned to one deadline/partition slot.
// All sector metadata (including PieceRoots) is embedded so the ZK prover can
// read piece files directly.
type PartitionMeta struct {
	DeadlineIndex  int          `json:"deadlineIndex"`
	PartitionIndex int          `json:"partitionIndex"`
	PartitionKind  string       `json:"partitionKind,omitempty"`
	CommittedBytes int64        `json:"committedBytes,omitempty"`
	ContentHash    string       `json:"contentHash,omitempty"`
	Sectors        []SectorMeta `json:"sectors"`
	Expiration     int64        `json:"expiration"` // min expiration across sectors
	LastProofRound uint64       `json:"lastProofRound,omitempty"`
	LastProofAt    string       `json:"lastProofAt,omitempty"`
}

// PartitionChallenge carries the on-chain challenge for a partition proof round.
type PartitionChallenge struct {
	PartitionKey  string `json:"partitionKey"`
	Round         uint64 `json:"round"`
	ChallengeSeed string `json:"challengeSeed"`
	CreatedAt     string `json:"createdAt"`
}

// ZKPartitionProofRequest is sent to the external partition ZK prover via stdin.
type ZKPartitionProofRequest struct {
	Partition    PartitionMeta      `json:"partition"`
	Challenge    PartitionChallenge `json:"challenge"`
	StorageDir   string             `json:"storageDir"`
	CircuitN     int                `json:"circuitN,omitempty"` // partition circuit capacity (padded sector count)
	CircuitM     int                `json:"circuitM,omitempty"` // challenges per sector
	PublicInputs []string           `json:"publicInputs,omitempty"`
}

type SectorReceipt struct {
	SectorID         string   `json:"sectorId"`
	SectorRoot       string   `json:"sectorRoot"`
	SectorExpiration int64    `json:"sectorExpiration"`
	PiecePosition    int      `json:"piecePosition"`
	InclusionProof   []string `json:"inclusionProof"`
}

type SectorChallenge struct {
	SectorRoot       string   `json:"sectorRoot"`
	Round            uint64   `json:"round"`
	ChallengeSeed    string   `json:"challengeSeed"`
	ChallengeIndexes []uint64 `json:"challengeIndexes"`
	CreatedAt        string   `json:"createdAt"`
}

type ZKProofRequest struct {
	Sector       SectorMeta      `json:"sector"`
	Challenge    SectorChallenge `json:"challenge"`
	StorageDir   string          `json:"storageDir"`
	PublicInputs []string        `json:"publicInputs,omitempty"`
}

type ZKProofResult struct {
	OK           bool     `json:"ok"`
	Err          string   `json:"err,omitempty"`
	SectorRoot   string   `json:"sectorRoot"`
	Round        uint64   `json:"round"`
	Proof        string   `json:"proof,omitempty"`
	PublicInputs []string `json:"publicInputs,omitempty"`
	GeneratedAt  string   `json:"generatedAt,omitempty"`
}

// ProofJob is the durable scheduling envelope for one reconstructible proof
// generation. The proof payload remains in the partition/snapshot journals;
// this record owns ordering, attempts, and host-resource admission only.
type ProofJob struct {
	ID              string `json:"id"`
	VKIdentity      string `json:"vkIdentity"`
	IdentityClass   string `json:"identityClass"`
	Generation      string `json:"generation"`
	Scope           string `json:"scope"`
	Work            string `json:"work"`
	Class           string `json:"class"`
	Resource        string `json:"resource"`
	State           string `json:"state"`
	CreatedUnixNano int64  `json:"createdUnixNano"`
	UpdatedUnixNano int64  `json:"updatedUnixNano"`
	DueUnixNano     int64  `json:"dueUnixNano"`
	NextAttemptNano int64  `json:"nextAttemptUnixNano,omitempty"`
	Attempts        int    `json:"attempts"`
	MaxAttempts     int    `json:"maxAttempts"`
	OwnerPID        int    `json:"ownerPid,omitempty"`
	OwnerStart      string `json:"ownerStart,omitempty"`
	LastError       string `json:"lastError,omitempty"`
}

type ProofSchedulerMetrics struct {
	QueuedByClass     map[string]int    `json:"queuedByClass"`
	FailedByClass     map[string]int    `json:"failedByClass"`
	DispatchedByClass map[string]uint64 `json:"dispatchedByClass"`
	OldestWaitNanos   map[string]int64  `json:"oldestWaitNanos"`
	Retrying          int               `json:"retrying"`
}

func nowRFC3339() string {
	return time.Now().Format(time.RFC3339)
}

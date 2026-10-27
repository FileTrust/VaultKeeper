package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// A.0 deployment-manifest verification.
//
// A running VK must be pinned to the exact contract stack it was configured for. The
// manifest (produced by Blockchain/scripts/generate_deployment_manifest.js) records, for
// every contract, its address, deployment block, deployment transaction hash, runtime code
// hash, ABI hash, and contract/interface version — plus the chain id, deployer, the exact
// deployed_addresses.json hash, and the wiring relationships. On startup the VK:
//   - rejects a chain-id or configured-address mismatch;
//   - fetches eth_getCode for every contract it uses and compares the runtime code hash;
//   - hashes the local ABI the chain-command uses and compares it to the manifest ABI hash;
//   - verifies every wiring relationship it relies upon (re-fetched from chain), not just
//     the snapshot edge;
//   - rejects missing required manifest fields;
//   - rejects a deployed_addresses.json whose hash or used-contract addresses differ.
// Every check fails closed. The RPC-backed checks (code hashes, wiring) run when an RPC URL
// is configured; the manifest-internal, ABI, and addresses-file checks run always.

type deploymentManifestContract struct {
	// New A.0 fields.
	ContractAddress           string `json:"contractAddress"`
	RuntimeCodeHash           string `json:"runtimeCodeHash"`
	DeploymentBlock           string `json:"deploymentBlock"`
	DeploymentTransactionHash string `json:"deploymentTransactionHash"`
	ContractVersion           string `json:"contractVersion"`
	// Back-compat aliases (also emitted by the generator).
	Address  string `json:"address"`
	CodeHash string `json:"codeHash"`
	ABIHash  string `json:"abiHash"`
}

func (c deploymentManifestContract) addr() string {
	if strings.TrimSpace(c.ContractAddress) != "" {
		return c.ContractAddress
	}
	return c.Address
}

func (c deploymentManifestContract) runtimeCodeHash() string {
	if strings.TrimSpace(c.RuntimeCodeHash) != "" {
		return c.RuntimeCodeHash
	}
	return c.CodeHash
}

type deploymentManifest struct {
	Version               int                                   `json:"version"`
	Schema                string                                `json:"schema"`
	ManifestKind          string                                `json:"manifestKind"`
	ChainID               string                                `json:"chainId"`
	GeneratedAt           string                                `json:"generatedAt"`
	Deployer              string                                `json:"deployer"`
	DeployedAddressesHash string                                `json:"deployedAddressesHash"`
	ContractInterfaceVer  string                                `json:"contractInterfaceVersion"`
	Contracts             map[string]deploymentManifestContract `json:"contracts"`
	Wiring                map[string]string                     `json:"wiring"`
	// ProofProfile is the deployed proof shape pinned at manifest generation (G.4B-LV0).
	ProofProfile deployedProofProfile `json:"proofProfile"`
}

func loadDeploymentManifest(path string) (deploymentManifest, error) {
	var m deploymentManifest
	payload, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(payload, &m); err != nil {
		return m, fmt.Errorf("decode deployment manifest: %w", err)
	}
	if m.ManifestKind != "filetrust-deployment-manifest" {
		return m, fmt.Errorf("not a filetrust deployment manifest: kind=%q", m.ManifestKind)
	}
	return m, nil
}

func addrEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// deploymentManifestVerifier carries the (injectable) chain and local ABI sources so the
// full enforcement is unit-testable without a live node or filesystem.
type deploymentManifestVerifier struct {
	// fetchCode returns the runtime bytecode ("0x..") at an address, or an error. Nil
	// disables the on-chain code-hash and wiring checks (manifest-internal + ABI +
	// addresses-file checks still run).
	fetchCode func(ctx context.Context, address string) (string, error)
	// fetchWiring returns the address a consumer's getter currently points at on-chain.
	// Nil disables the on-chain wiring re-fetch (the manifest-internal wiring invariant is
	// still checked).
	fetchWiring func(ctx context.Context, consumerAddress, getter string) (string, error)
	// localABIHash returns the keccak256 (0x..) of the ABI JSON the process uses for a
	// contract, or ("", false) if that contract's ABI is not held locally. Nil disables
	// the ABI check.
	localABIHash func(contractName string) (string, bool)
	// deployedAddressesPath, when set, is hashed and its addresses compared to the manifest.
	deployedAddressesPath string
}

// wiring edges every VK relies upon (not only the snapshot edge).
var deploymentManifestRequiredWiring = []struct {
	consumer string
	getter   string
	target   string // manifest contract whose address the edge must equal
}{
	{"StorageProofSC", "partitionSnapshotProof", "PartitionSnapshotProofSC"},
	{"StorageProofSC", "capacityProof", "CapacityProofSC"},
	{"CapacityProofSC", "partitionSnapshotProof", "PartitionSnapshotProofSC"},
	{"CapacityProofSC", "storageProof", "StorageProofSC"},
	{"PartitionSnapshotProofSC", "storageProof", "StorageProofSC"},
	{"PartitionSnapshotProofSC", "capacityProof", "CapacityProofSC"},
	// G.1A: the capacity certification authority edge must be reciprocal in both directions,
	// or the stack is pointing at a certification ring that will reject every write.
	{"CapacityProofSC", "certificationContract", "CapacityCertificationSC"},
	{"CapacityCertificationSC", "capacityProofSC", "CapacityProofSC"},
	// G.2A: exact incremental membership is only enforceable when the snapshot contract and
	// the batch contract are reciprocally bound and the batch reads the same CapacityProofSC.
	{"PartitionSnapshotProofSC", "incrementalBatch", "CapacityIncrementalBatchSC"},
	{"CapacityIncrementalBatchSC", "snapshotProof", "PartitionSnapshotProofSC"},
	{"CapacityIncrementalBatchSC", "capacityProof", "CapacityProofSC"},
	{"FileRegistrationSC", "deletionRelease", "DeletionReleaseSC"},
	{"PartitionSnapshotProofSC", "deletionRelease", "DeletionReleaseSC"},
	{"StorageProofSC", "deletionRelease", "DeletionReleaseSC"},
	{"DeletionReleaseSC", "fileRegistration", "FileRegistrationSC"},
	{"DeletionReleaseSC", "snapshotProof", "PartitionSnapshotProofSC"},
	{"DeletionReleaseSC", "storageProof", "StorageProofSC"},
}

func keccakHex(data []byte) string {
	return "0x" + hex.EncodeToString(ethcrypto.Keccak256(data))
}

// verify runs the full enforcement. usedContracts maps manifest contract name → the
// configured address the VK will call ("" means the VK does not use it).
func (v deploymentManifestVerifier) verify(ctx context.Context, m deploymentManifest, chainID int64, usedContracts map[string]string) error {
	// --- required top-level fields ------------------------------------------------------
	if strings.TrimSpace(m.Schema) == "" {
		return fmt.Errorf("manifest missing schema identifier")
	}
	if strings.TrimSpace(m.DeployedAddressesHash) == "" {
		return fmt.Errorf("manifest missing deployedAddressesHash")
	}
	if strings.TrimSpace(m.ChainID) != fmt.Sprintf("%d", chainID) {
		return fmt.Errorf("manifest chainId %s != configured chainId %d", m.ChainID, chainID)
	}

	// --- per-contract required fields + config/address binding --------------------------
	needed := map[string]bool{"PartitionSnapshotProofSC": true}
	for name, cfgAddr := range usedContracts {
		if cfgAddr != "" {
			needed[name] = true
		}
	}
	for name := range needed {
		entry, ok := m.Contracts[name]
		if !ok {
			return fmt.Errorf("manifest missing required contract %s", name)
		}
		if strings.TrimSpace(entry.addr()) == "" || strings.TrimSpace(entry.runtimeCodeHash()) == "" ||
			strings.TrimSpace(entry.ABIHash) == "" || strings.TrimSpace(entry.DeploymentBlock) == "" ||
			strings.TrimSpace(entry.DeploymentTransactionHash) == "" || strings.TrimSpace(entry.ContractVersion) == "" {
			return fmt.Errorf("manifest contract %s is missing required fields (address/runtimeCodeHash/abiHash/deploymentBlock/deploymentTransactionHash/contractVersion)", name)
		}
		if cfgAddr := usedContracts[name]; cfgAddr != "" && !addrEqual(entry.addr(), cfgAddr) {
			return fmt.Errorf("manifest %s address %s != configured %s (wrong or partially-migrated stack?)", name, entry.addr(), cfgAddr)
		}
	}

	// --- manifest-internal wiring invariant (cheap, always) -----------------------------
	for _, w := range deploymentManifestRequiredWiring {
		if _, need := needed[w.consumer]; !need {
			continue
		}
		target, ok := m.Contracts[w.target]
		if !ok {
			return fmt.Errorf("manifest wiring target %s missing", w.target)
		}
		edge := w.consumer + "." + w.getter
		got, ok := m.Wiring[edge]
		if !ok {
			return fmt.Errorf("manifest missing wiring edge %s", edge)
		}
		if !addrEqual(got, target.addr()) {
			return fmt.Errorf("manifest wiring %s %s != %s %s", edge, got, w.target, target.addr())
		}
	}

	// --- deployed_addresses.json hash + addresses ---------------------------------------
	if strings.TrimSpace(v.deployedAddressesPath) != "" {
		raw, err := os.ReadFile(v.deployedAddressesPath)
		if err != nil {
			return fmt.Errorf("read deployed_addresses.json: %w", err)
		}
		if got := keccakHex(raw); !strings.EqualFold(got, m.DeployedAddressesHash) {
			return fmt.Errorf("deployed_addresses.json hash %s != manifest %s", got, m.DeployedAddressesHash)
		}
		var da struct {
			// deployed_addresses.json also publishes structured lookup tables (for
			// example ShareVerifierByCommittee) beside ordinary address strings.
			// Decode values independently so unrelated objects cannot make the VK
			// reject an otherwise exact, hash-bound production deployment file.
			Contracts map[string]json.RawMessage `json:"contracts"`
		}
		if err := json.Unmarshal(raw, &da); err != nil {
			return fmt.Errorf("decode deployed_addresses.json: %w", err)
		}
		for name := range needed {
			encoded, ok := da.Contracts[name]
			if !ok {
				return fmt.Errorf("deployed_addresses.json missing required contract %s", name)
			}
			var a string
			if err := json.Unmarshal(encoded, &a); err != nil || strings.TrimSpace(a) == "" {
				return fmt.Errorf("deployed_addresses.json %s is not an address string", name)
			}
			if !addrEqual(a, m.Contracts[name].addr()) {
				return fmt.Errorf("deployed_addresses.json %s %s != manifest %s", name, a, m.Contracts[name].addr())
			}
		}
	}

	// --- local ABI hash ------------------------------------------------------------------
	if v.localABIHash != nil {
		for name := range needed {
			if h, ok := v.localABIHash(name); ok {
				if !strings.EqualFold(h, m.Contracts[name].ABIHash) {
					return fmt.Errorf("local ABI hash for %s %s != manifest %s (stale ABI?)", name, h, m.Contracts[name].ABIHash)
				}
			}
		}
	}

	// --- on-chain runtime code hashes ----------------------------------------------------
	if v.fetchCode != nil {
		for name := range needed {
			entry := m.Contracts[name]
			code, err := v.fetchCode(ctx, entry.addr())
			if err != nil {
				return fmt.Errorf("eth_getCode %s: %w", name, err)
			}
			codeBytes, decErr := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(code), "0x"))
			if decErr != nil {
				return fmt.Errorf("decode code for %s: %w", name, decErr)
			}
			if len(codeBytes) == 0 {
				return fmt.Errorf("no runtime code at %s (%s)", name, entry.addr())
			}
			if got := keccakHex(codeBytes); !strings.EqualFold(got, entry.runtimeCodeHash()) {
				return fmt.Errorf("on-chain runtime code hash for %s %s != manifest %s (altered bytecode?)", name, got, entry.runtimeCodeHash())
			}
		}
	}

	// --- on-chain wiring re-fetch --------------------------------------------------------
	if v.fetchWiring != nil {
		for _, w := range deploymentManifestRequiredWiring {
			if _, need := needed[w.consumer]; !need {
				continue
			}
			consumer := m.Contracts[w.consumer].addr()
			want := m.Contracts[w.target].addr()
			got, err := v.fetchWiring(ctx, consumer, w.getter)
			if err != nil {
				return fmt.Errorf("wiring fetch %s.%s: %w", w.consumer, w.getter, err)
			}
			if !addrEqual(got, want) {
				return fmt.Errorf("on-chain wiring %s.%s %s != %s (%s)", w.consumer, w.getter, got, w.target, want)
			}
		}
	}
	return nil
}

// manifestABIFingerprint is a stable digest of the manifest's contract identities, for
// logging which stack a VK bound to.
func manifestABIFingerprint(m deploymentManifest) string {
	parts := make([]string, 0, len(m.Contracts))
	for name, c := range m.Contracts {
		parts = append(parts, name+":"+c.addr()+":"+c.runtimeCodeHash()+":"+c.ABIHash)
	}
	sum := sha256.Sum256([]byte(m.ChainID + "|" + strings.Join(parts, ";")))
	return hex.EncodeToString(sum[:8])
}

// realDeploymentManifestVerifier builds the production verifier from cfg: eth_getCode and
// wiring are fetched over RPC when RPCURL is set; the snapshot ABI is hashed from the
// core-contracts copy the chain-command uses; deployed_addresses.json is verified when a
// path is provided (DeploymentAddressesPath).
func realDeploymentManifestVerifier(cfg ServerConfig) deploymentManifestVerifier {
	v := deploymentManifestVerifier{deployedAddressesPath: cfg.DeployedAddressesPath}
	if strings.TrimSpace(cfg.RPCURL) != "" {
		v.fetchCode = func(ctx context.Context, address string) (string, error) {
			return rpcCallCtx(ctx, cfg.RPCURL, "eth_getCode", []any{address, "latest"})
		}
		v.fetchWiring = func(ctx context.Context, consumer, getter string) (string, error) {
			return ethCallAddressGetter(ctx, cfg.RPCURL, consumer, getter)
		}
	}
	v.localABIHash = func(name string) (string, bool) {
		// The chain command uses the core-contracts ABI copies; hash the ones the VK ships.
		path := "core/contracts/" + name + ".json"
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", false
		}
		var artifact struct {
			ABI json.RawMessage `json:"abi"`
		}
		if err := json.Unmarshal(raw, &artifact); err != nil || len(artifact.ABI) == 0 {
			return "", false
		}
		// Match the generator: keccak256 of the compact ABI JSON.
		compact, err := json.Marshal(artifact.ABI)
		if err != nil {
			return "", false
		}
		return keccakHex(compact), true
	}
	return v
}

// ethCallAddressGetter calls a zero-arg address-returning getter (selector = first 4 bytes
// of keccak256("name()")) and decodes the trailing 20 bytes of the 32-byte return word.
func ethCallAddressGetter(ctx context.Context, rpcURL, contract, getter string) (string, error) {
	selector := ethcrypto.Keccak256([]byte(getter + "()"))[:4]
	data := "0x" + hex.EncodeToString(selector)
	result, err := rpcCallCtx(ctx, rpcURL, "eth_call", []any{
		map[string]string{"to": contract, "data": data}, "latest",
	})
	if err != nil {
		return "", err
	}
	h := strings.TrimPrefix(strings.TrimSpace(result), "0x")
	if len(h) < 64 {
		return "", fmt.Errorf("short eth_call result for %s.%s", contract, getter)
	}
	return "0x" + h[24:64], nil
}

// enforceDeploymentManifest loads and verifies the manifest at path against cfg. A missing
// path is skipped (opt-in), but a present-and-invalid manifest, or any mismatch, is fatal.
func enforceDeploymentManifest(path string, cfg ServerConfig) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	m, err := loadDeploymentManifest(path)
	if err != nil {
		return fmt.Errorf("deployment manifest: %w", err)
	}
	used := map[string]string{
		"StorageProofSC":     cfg.StorageProofContract,
		"CapacityProofSC":    cfg.CapacityProofContract,
		"FileRegistrationSC": cfg.FileRegistrationContract,
		"DeletionReleaseSC":  cfg.DeletionReleaseContract,
	}
	if err := realDeploymentManifestVerifier(cfg).verify(context.Background(), m, cfg.ChainID, used); err != nil {
		return fmt.Errorf("deployment manifest verification failed: %w", err)
	}
	return nil
}

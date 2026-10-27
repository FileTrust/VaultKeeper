package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

var vkRegMu sync.Mutex

func hasRegistryMethod(parsedABI abi.ABI, name string) bool {
	_, ok := parsedABI.Methods[name]
	return ok
}

func maxPieceSizeForRegistry(cfg ServerConfig) uint64 {
	if cfg.MaxPieceSizeBytes <= 0 {
		return 0
	}
	return uint64(cfg.MaxPieceSizeBytes)
}

func vaultKeeperEligibleOnChain(cfg ServerConfig) (bool, error) {
	if cfg.VKRegistryContract == "" {
		return false, fmt.Errorf("VaultKeeperRegistry not configured")
	}
	if cfg.RPCURL == "" {
		return false, fmt.Errorf("RPC URL not configured")
	}
	selector := common.Bytes2Hex(
		ethcrypto.Keccak256([]byte("isEligibleVaultKeeper(address)"))[:4],
	)
	addressWord := common.LeftPadBytes(common.HexToAddress(cfg.VKAddress).Bytes(), 32)
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{
			"to":   common.HexToAddress(cfg.VKRegistryContract).Hex(),
			"data": "0x" + selector + hex.EncodeToString(addressWord),
		},
		"latest",
	})
	if err != nil {
		return false, err
	}
	value, ok := new(big.Int).SetString(strings.TrimPrefix(result, "0x"), 16)
	if !ok {
		return false, fmt.Errorf("invalid eligibility response: %q", result)
	}
	return value.Sign() != 0, nil
}

// registerSelfInRegistry sends registerVaultKeeper (or updateVaultKeeper if already
// registered) to VaultKeeperRegistry, signed with the VK's own private key.
// Returns true only after the registry returns this exact peerID for the VK address.
func registerSelfInRegistry(cfg ServerConfig, peerID, multiaddr string) bool {
	if cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" {
		// Every other early return here logs its reason; without this line a pure
		// misconfiguration is indistinguishable from a chain/registration failure and the
		// caller only ever prints "registration still unconfirmed".
		log.Printf("[vk_reg] skipped: --vk-registry-contract or --vk-registry-abi not set (contract=%q abi=%q)",
			cfg.VKRegistryContract, cfg.VKRegistryABIPath)
		return false
	}
	if cfg.VKPrivKeyHex == "" {
		log.Printf("[vk_reg] skipped: --vk-private-key not set")
		return false
	}
	if cfg.RPCURL == "" {
		log.Printf("[vk_reg] skipped: --rpc-url not set")
		return false
	}
	if cfg.ChainID == 0 {
		log.Printf("[vk_reg] skipped: --chain-id not set")
		return false
	}

	raw, err := os.ReadFile(cfg.VKRegistryABIPath)
	if err != nil {
		log.Printf("[vk_reg] read ABI file: %v", err)
		return false
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	abiJSON := raw
	if json.Unmarshal(raw, &artifact) == nil && len(artifact.ABI) > 2 {
		abiJSON = artifact.ABI
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		log.Printf("[vk_reg] parse ABI: %v", err)
		return false
	}

	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		log.Printf("[vk_reg] invalid private key: %v", err)
		return false
	}
	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.VKRegistryContract)

	// Check if already registered.
	isRegData, err := parsedABI.Pack("isRegisteredVaultKeeper", fromAddr)
	if err != nil {
		log.Printf("[vk_reg] pack isRegisteredVaultKeeper: %v", err)
		return false
	}
	callResult, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": toAddr.Hex(), "data": "0x" + hex.EncodeToString(isRegData)},
		"latest",
	})
	logEthCall("vk:VaultKeeperRegistry.isRegisteredVaultKeeper", cfg.RPCURL, cfg.ChainID, "VaultKeeperRegistry", "isRegisteredVaultKeeper", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{})
	if err != nil {
		log.Printf("[vk_reg] isRegisteredVaultKeeper call: %v", err)
		return false
	}
	// ABI bool is a 32-byte word; last hex char is '1' for true, '0' for false.
	trimmed := strings.TrimPrefix(callResult, "0x")
	isRegistered := len(trimmed) == 64 && trimmed[63] == '1'

	metaJSON, _ := json.Marshal(map[string]any{
		"name":              fmt.Sprintf("VK %s", cfg.VKAddress),
		"type":              "vaultmesh-sector-vk",
		"peerId":            peerID,
		"maxPieceSizeBytes": maxPieceSizeForRegistry(cfg),
	})
	storageFee := big.NewInt(cfg.StorageFee)
	stakeWei := new(big.Int)
	if _, ok := stakeWei.SetString(cfg.StakeWei, 10); !ok {
		stakeWei = big.NewInt(0)
	}

	maxServiceDays := uint32(cfg.MaxServiceDays)
	maxPieceSizeBytes := maxPieceSizeForRegistry(cfg)
	var calldata []byte
	var value *big.Int
	targetFn := "registerVaultKeeper"
	usedCapacityMethod := false
	if isRegistered {
		if hasRegistryMethod(parsedABI, "updateVaultKeeperWithCapacity") {
			targetFn = "updateVaultKeeperWithCapacity"
			usedCapacityMethod = true
			calldata, err = parsedABI.Pack("updateVaultKeeperWithCapacity", peerID, string(metaJSON), storageFee, maxServiceDays, maxPieceSizeBytes)
		} else {
			targetFn = "updateVaultKeeper"
			calldata, err = parsedABI.Pack("updateVaultKeeper", peerID, string(metaJSON), storageFee, maxServiceDays)
		}
		value = big.NewInt(0)
		log.Printf("[vk_reg] updating registration  addr=%s  maxServiceDays=%d  maxPieceSizeBytes=%d", cfg.VKAddress, maxServiceDays, maxPieceSizeBytes)
	} else {
		if hasRegistryMethod(parsedABI, "registerVaultKeeperWithCapacity") {
			targetFn = "registerVaultKeeperWithCapacity"
			usedCapacityMethod = true
			calldata, err = parsedABI.Pack("registerVaultKeeperWithCapacity", peerID, string(metaJSON), storageFee, maxServiceDays, maxPieceSizeBytes)
		} else {
			calldata, err = parsedABI.Pack("registerVaultKeeper", peerID, string(metaJSON), storageFee, maxServiceDays)
		}
		minimum, minErr := readMinimumVaultKeeperStake(cfg, parsedABI, toAddr)
		if minErr != nil {
			log.Printf("[vk_reg] could not read the chain's minimum stake (%v); sending the configured stake", minErr)
		}
		value = registrationStake(stakeWei, minimum)
		if value.Cmp(stakeWei) != 0 {
			log.Printf("[vk_reg] configured stake %s wei is below the chain minimum %s wei; staking the minimum", stakeWei, value)
		}
		log.Printf("[vk_reg] self-registering  addr=%s  stake=%s wei  maxServiceDays=%d  maxPieceSizeBytes=%d", cfg.VKAddress, value.String(), maxServiceDays, maxPieceSizeBytes)
	}
	if err != nil {
		log.Printf("[vk_reg] pack calldata: %v", err)
		return false
	}

	vkRegMu.Lock()
	defer vkRegMu.Unlock()
	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		log.Printf("[vk_reg] account transaction lock: %v", err)
		return false
	}
	defer accountLock.Release()

	nonce, err := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(err), map[string]any{
		"nonce":           nonce,
		"target_function": "registerOrUpdateVaultKeeper",
	})
	if err != nil {
		log.Printf("[vk_reg] get nonce: %v", err)
		return false
	}
	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	logEthCall("vk:eth.gasPrice", cfg.RPCURL, cfg.ChainID, "eth", "gasPrice", "", fromAddr.Hex(), "success", map[string]any{
		"result":          gasPrice.String(),
		"target_function": "registerOrUpdateVaultKeeper",
	})
	gasLimit, err := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, value)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": targetFn,
	})
	if err != nil && usedCapacityMethod {
		legacyFn := "registerVaultKeeper"
		if isRegistered {
			legacyFn = "updateVaultKeeper"
		}
		legacyCalldata, packErr := parsedABI.Pack(legacyFn, peerID, string(metaJSON), storageFee, maxServiceDays)
		if packErr == nil {
			log.Printf("[vk_reg] capacity method %s unavailable on deployed registry; retrying %s: %v", targetFn, legacyFn, err)
			targetFn = legacyFn
			calldata = legacyCalldata
			usedCapacityMethod = false
			gasLimit, err = rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, value)
			logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{
				"gas_estimate":    gasLimit,
				"target_function": targetFn,
				"fallback":        true,
			})
		}
	}
	if err != nil {
		log.Printf("[vk_reg] estimateGas: %v", err)
		return false
	}
	gasLimit = gasLimit * 12 / 10

	tx := types.NewTransaction(nonce, toAddr, value, gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(big.NewInt(cfg.ChainID))
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		log.Printf("[vk_reg] sign tx: %v", err)
		return false
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		log.Printf("[vk_reg] marshal tx: %v", err)
		return false
	}
	txHash, err := rpcSendRawTransaction(cfg.RPCURL, rawTx)
	details := map[string]any{
		"peer_id": peerID,
	}
	if err == nil {
		if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
			logMinedTx("vk:VaultKeeperRegistry."+targetFn, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "VaultKeeperRegistry", targetFn, toAddr.Hex(), signedTx, receipt, details)
		} else {
			if receiptErr != nil {
				log.Printf("[vk_reg] receipt wait failed; logging submitted tx only: %v", receiptErr)
			}
			logSubmittedTx("vk:VaultKeeperRegistry."+targetFn, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "VaultKeeperRegistry", targetFn, toAddr.Hex(), signedTx, txHash, details)
		}
	}
	if err != nil {
		log.Printf("[vk_reg] send tx: %v", err)
		return false
	}
	action := "registered"
	if isRegistered {
		action = "updated"
	}
	log.Printf("[vk_reg] %s  addr=%s  tx=%s", action, cfg.VKAddress, txHash)
	return waitForRegistryPeerID(cfg.RPCURL, parsedABI, toAddr, fromAddr, peerID, 30*time.Second)
}

// readMinimumVaultKeeperStake is the stake the registry requires for a new
// keeper (VaultKeeperRegistry.minimumVaultKeeperStake), read from the chain.
func readMinimumVaultKeeperStake(cfg ServerConfig, parsedABI abi.ABI, registry common.Address) (*big.Int, error) {
	if !hasRegistryMethod(parsedABI, "minimumVaultKeeperStake") {
		return nil, fmt.Errorf("registry ABI has no minimumVaultKeeperStake")
	}
	data, err := parsedABI.Pack("minimumVaultKeeperStake")
	if err != nil {
		return nil, err
	}
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": registry.Hex(), "data": "0x" + hex.EncodeToString(data)},
		"latest",
	})
	logEthCall("vk:VaultKeeperRegistry.minimumVaultKeeperStake", cfg.RPCURL, cfg.ChainID, "VaultKeeperRegistry",
		"minimumVaultKeeperStake", registry.Hex(), cfg.VKAddress, statusFromErr(err), map[string]any{})
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(result, "0x"))
	if err != nil || len(raw) < 32 {
		return nil, fmt.Errorf("bad minimumVaultKeeperStake result %q", result)
	}
	return new(big.Int).SetBytes(raw[:32]), nil
}

// registrationStake is the stake sent with a first registration: the configured
// amount, raised to the chain's minimum when that is higher. The registry refuses
// anything below its minimum, so a configured amount made for another deployment
// would otherwise keep the keeper out of the network. Guardians do the same.
func registrationStake(configured, minimum *big.Int) *big.Int {
	// No minimum, or the registry's "no staking manager" answer
	// (type(uint256).max, which nobody can pay): send what is configured.
	if minimum == nil || minimum.Sign() <= 0 || minimum.BitLen() > 128 {
		return configured
	}
	if configured.Cmp(minimum) < 0 {
		return new(big.Int).Set(minimum)
	}
	return configured
}

type registryEndpointStatus struct {
	EndpointHash string
	Seq          uint64
	UpdatedAt    uint64
}

func syncRegistryEndpoint(cfg ServerConfig, peerID, multiaddr string, localSeq int64) (int64, string, bool) {
	if cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" {
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		log.Printf("[vk_reg] endpoint update required but VaultKeeperRegistry contract/ABI is missing")
		return localSeq, discoveryEndpointHash(record), false
	}
	if cfg.VKPrivKeyHex == "" || cfg.RPCURL == "" || cfg.ChainID == 0 {
		log.Printf("[vk_reg] endpoint update skipped: private key, rpc-url, and chain-id are required")
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		return localSeq, discoveryEndpointHash(record), false
	}

	raw, err := os.ReadFile(cfg.VKRegistryABIPath)
	if err != nil {
		log.Printf("[vk_reg] read ABI file for endpoint update: %v", err)
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		return localSeq, discoveryEndpointHash(record), false
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	abiJSON := raw
	if json.Unmarshal(raw, &artifact) == nil && len(artifact.ABI) > 2 {
		abiJSON = artifact.ABI
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		log.Printf("[vk_reg] parse ABI for endpoint update: %v", err)
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		return localSeq, discoveryEndpointHash(record), false
	}

	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.VKRegistryContract)
	current, supported, err := readRegistryEndpoint(cfg, parsedABI, toAddr, fromAddr)
	if !supported {
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		endpointHash := discoveryEndpointHash(record)
		log.Printf("[vk_reg] endpoint hash required but registry ABI/contract does not support getVaultKeeperEndpoint")
		return localSeq, endpointHash, false
	}
	if err != nil {
		log.Printf("[vk_reg] getVaultKeeperEndpoint failed: %v", err)
		record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
		return localSeq, discoveryEndpointHash(record), false
	}

	if localSeq <= 0 {
		localSeq = time.Now().UTC().UnixNano()
	}
	record := DiscoveryRecord{Version: 1, PeerID: peerID, Multiaddr: multiaddr, VKAddress: cfg.VKAddress, Seq: localSeq}
	endpointHash := discoveryEndpointHash(record)

	if strings.EqualFold(current.EndpointHash, endpointHash) && current.Seq == uint64(localSeq) {
		return localSeq, endpointHash, true
	}
	if current.Seq >= uint64(localSeq) {
		nextSeq := time.Now().UTC().UnixNano()
		if uint64(nextSeq) <= current.Seq {
			nextSeq = int64(current.Seq + 1)
		}
		localSeq = nextSeq
		record.Seq = localSeq
		endpointHash = discoveryEndpointHash(record)
	}

	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		log.Printf("[vk_reg] invalid private key for endpoint update: %v", err)
		return localSeq, endpointHash, false
	}
	calldata, err := parsedABI.Pack("updateEndpoint", common.HexToHash(endpointHash), uint64(localSeq))
	if err != nil {
		log.Printf("[vk_reg] pack updateEndpoint: %v", err)
		return localSeq, endpointHash, false
	}
	ok := sendVKRegistryTransaction(
		cfg,
		toAddr,
		fromAddr,
		privKey,
		"updateEndpoint",
		calldata,
		big.NewInt(0),
		map[string]any{"endpoint_hash": endpointHash, "endpoint_seq": localSeq, "peer_id": peerID},
	)
	if ok {
		log.Printf("[vk_reg] endpoint updated  addr=%s  seq=%d  hash=%s", cfg.VKAddress, localSeq, endpointHash)
	}
	return localSeq, endpointHash, ok
}

func readRegistryEndpoint(
	cfg ServerConfig,
	parsedABI abi.ABI,
	registryAddr common.Address,
	vkAddr common.Address,
) (registryEndpointStatus, bool, error) {
	data, err := parsedABI.Pack("getVaultKeeperEndpoint", vkAddr)
	if err != nil {
		return registryEndpointStatus{}, false, nil
	}
	result, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": registryAddr.Hex(), "data": "0x" + hex.EncodeToString(data)},
		"latest",
	})
	logEthCall("vk:VaultKeeperRegistry.getVaultKeeperEndpoint", cfg.RPCURL, cfg.ChainID, "VaultKeeperRegistry", "getVaultKeeperEndpoint", registryAddr.Hex(), vkAddr.Hex(), statusFromErr(err), map[string]any{})
	if err != nil {
		if isEndpointUnsupportedError(err) {
			return registryEndpointStatus{}, false, nil
		}
		return registryEndpointStatus{}, true, err
	}
	clean := strings.TrimPrefix(result, "0x")
	if clean == "" {
		return registryEndpointStatus{}, false, nil
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return registryEndpointStatus{}, true, fmt.Errorf("decode endpoint result: %w", err)
	}
	values, err := parsedABI.Unpack("getVaultKeeperEndpoint", raw)
	if err != nil {
		return registryEndpointStatus{}, true, fmt.Errorf("unpack endpoint result: %w", err)
	}
	if len(values) < 3 {
		return registryEndpointStatus{}, true, fmt.Errorf("bad endpoint result")
	}
	return registryEndpointStatus{
		EndpointHash: abiBytes32Hex(values[0]),
		Seq:          abiUint64(values[1]),
		UpdatedAt:    abiUint64(values[2]),
	}, true, nil
}

func isEndpointUnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "function selector") ||
		strings.Contains(msg, "not recognized") ||
		strings.Contains(msg, "function does not exist") ||
		strings.Contains(msg, "could not decode") ||
		strings.Contains(msg, "return data: b''")
}

func abiBytes32Hex(value any) string {
	switch v := value.(type) {
	case [32]byte:
		return common.BytesToHash(v[:]).Hex()
	case common.Hash:
		return v.Hex()
	case []byte:
		return common.BytesToHash(v).Hex()
	default:
		return common.Hash{}.Hex()
	}
}

func abiUint64(value any) uint64 {
	switch v := value.(type) {
	case uint8:
		return uint64(v)
	case uint16:
		return uint64(v)
	case uint32:
		return uint64(v)
	case uint64:
		return v
	case *big.Int:
		return v.Uint64()
	default:
		return 0
	}
}

func sendVKRegistryTransaction(
	cfg ServerConfig,
	toAddr common.Address,
	fromAddr common.Address,
	privKey *ecdsa.PrivateKey,
	functionName string,
	calldata []byte,
	value *big.Int,
	details map[string]any,
) bool {
	vkRegMu.Lock()
	defer vkRegMu.Unlock()
	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		log.Printf("[vk_reg] account transaction lock for %s: %v", functionName, err)
		return false
	}
	defer accountLock.Release()

	nonce, err := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	logEthCall("vk:eth.getTransactionCount", cfg.RPCURL, cfg.ChainID, "eth", "getTransactionCount", "", fromAddr.Hex(), statusFromErr(err), map[string]any{
		"nonce":           nonce,
		"target_function": functionName,
	})
	if err != nil {
		log.Printf("[vk_reg] get nonce for %s: %v", functionName, err)
		return false
	}
	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	logEthCall("vk:eth.gasPrice", cfg.RPCURL, cfg.ChainID, "eth", "gasPrice", "", fromAddr.Hex(), "success", map[string]any{
		"result":          gasPrice.String(),
		"target_function": functionName,
	})
	gasLimit, err := rpcEstimateGas(cfg.RPCURL, fromAddr.Hex(), toAddr.Hex(), calldata, value)
	logEthCall("vk:eth.estimateGas", cfg.RPCURL, cfg.ChainID, "eth", "estimateGas", toAddr.Hex(), fromAddr.Hex(), statusFromErr(err), map[string]any{
		"gas_estimate":    gasLimit,
		"target_function": functionName,
	})
	if err != nil {
		log.Printf("[vk_reg] estimateGas for %s: %v", functionName, err)
		return false
	}
	gasLimit = gasLimit * 12 / 10

	tx := types.NewTransaction(nonce, toAddr, value, gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(big.NewInt(cfg.ChainID))
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		log.Printf("[vk_reg] sign %s tx: %v", functionName, err)
		return false
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		log.Printf("[vk_reg] marshal %s tx: %v", functionName, err)
		return false
	}
	txHash, err := rpcSendRawTransaction(cfg.RPCURL, rawTx)
	if err == nil {
		if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
			logMinedTx("vk:VaultKeeperRegistry."+functionName, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "VaultKeeperRegistry", functionName, toAddr.Hex(), signedTx, receipt, details)
			if decimalFromHex(receipt.Status) != "1" {
				log.Printf("[vk_reg] %s reverted tx=%s", functionName, txHash)
				return false
			}
		} else {
			if receiptErr != nil {
				log.Printf("[vk_reg] %s receipt wait failed; logging submitted tx only: %v", functionName, receiptErr)
			}
			logSubmittedTx("vk:VaultKeeperRegistry."+functionName, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(), "VaultKeeperRegistry", functionName, toAddr.Hex(), signedTx, txHash, details)
		}
	}
	if err != nil {
		log.Printf("[vk_reg] send %s tx: %v", functionName, err)
		return false
	}
	return true
}

func waitForRegistryPeerID(
	rpcURL string,
	parsedABI abi.ABI,
	registryAddr common.Address,
	vkAddr common.Address,
	peerID string,
	timeout time.Duration,
) bool {
	deadline := time.Now().Add(timeout)
	for {
		ok, currentPeerID, err := registryPeerIDMatches(rpcURL, parsedABI, registryAddr, vkAddr, peerID)
		if ok {
			log.Printf("[vk_reg] confirmed peerId in registry  addr=%s  peerId=%s", vkAddr.Hex(), peerID)
			return true
		}
		if err != nil {
			log.Printf("[vk_reg] waiting for registry confirmation: %v", err)
		} else if currentPeerID != "" {
			log.Printf("[vk_reg] waiting for registry peerId update  current=%s expected=%s", currentPeerID, peerID)
		}
		if time.Now().After(deadline) {
			log.Printf("[vk_reg] registry confirmation timed out  addr=%s  peerId=%s", vkAddr.Hex(), peerID)
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func registryPeerIDMatches(
	rpcURL string,
	parsedABI abi.ABI,
	registryAddr common.Address,
	vkAddr common.Address,
	expectedPeerID string,
) (bool, string, error) {
	// peerId is no longer in contract storage — it lives in the VaultKeeperRegistered event.
	// Confirm registration by checking isRegisteredVaultKeeper; the contract rejects empty
	// peerIds so a successful tx guarantees the correct peerId was recorded on-chain.
	data, err := parsedABI.Pack("isRegisteredVaultKeeper", vkAddr)
	if err != nil {
		return false, "", fmt.Errorf("pack isRegisteredVaultKeeper: %w", err)
	}
	result, err := rpcCall(rpcURL, "eth_call", []any{
		map[string]string{"to": registryAddr.Hex(), "data": "0x" + hex.EncodeToString(data)},
		"latest",
	})
	logEthCall("vk:VaultKeeperRegistry.isRegisteredVaultKeeper", rpcURL, 0, "VaultKeeperRegistry", "isRegisteredVaultKeeper", registryAddr.Hex(), vkAddr.Hex(), statusFromErr(err), map[string]any{})
	if err != nil {
		return false, "", fmt.Errorf("isRegisteredVaultKeeper call: %w", err)
	}
	trimmed := strings.TrimPrefix(result, "0x")
	if len(trimmed) == 64 && trimmed[63] == '1' {
		return true, expectedPeerID, nil
	}
	return false, "", nil
}

func extractPeerIDFromABIValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if v.Kind() == reflect.Struct {
		for _, name := range []string{"PeerId", "PeerID", "peerId"} {
			field := v.FieldByName(name)
			if field.IsValid() && field.Kind() == reflect.String {
				return field.String()
			}
		}
		if v.NumField() > 1 {
			field := v.Field(1)
			if field.Kind() == reflect.String {
				return field.String()
			}
		}
	}
	if (v.Kind() == reflect.Slice || v.Kind() == reflect.Array) && v.Len() > 1 {
		field := v.Index(1)
		if field.Kind() == reflect.Interface {
			field = field.Elem()
		}
		if field.Kind() == reflect.String {
			return field.String()
		}
	}
	return ""
}

func decodeVaultKeeperPeerID(raw []byte) string {
	if len(raw) < 64 {
		return ""
	}
	candidates := []int{0}
	if offset := abiWordToInt(raw[0:32]); offset >= 0 {
		candidates = append(candidates, offset)
	}
	for _, base := range candidates {
		if peerID, ok := decodeABIStringSlot(raw, base, 1); ok {
			return peerID
		}
	}
	return ""
}

func decodeABIStringSlot(raw []byte, tupleBase int, slot int) (string, bool) {
	slotStart := tupleBase + slot*32
	if tupleBase < 0 || slotStart < 0 || slotStart+32 > len(raw) {
		return "", false
	}
	offset := abiWordToInt(raw[slotStart : slotStart+32])
	if offset < 0 {
		return "", false
	}
	valueStart := tupleBase + offset
	if valueStart < 0 || valueStart+32 > len(raw) {
		return "", false
	}
	length := abiWordToInt(raw[valueStart : valueStart+32])
	if length < 0 || valueStart+32+length > len(raw) {
		return "", false
	}
	return string(raw[valueStart+32 : valueStart+32+length]), true
}

func abiWordToInt(word []byte) int {
	if len(word) != 32 {
		return -1
	}
	value := new(big.Int).SetBytes(word)
	if value.BitLen() > 31 {
		return -1
	}
	return int(value.Int64())
}

type registryAdmissionStatus struct {
	Closed    bool
	FreeBytes uint64
	Supported bool
}

// registryDisagreesWithAdmission reports whether the registry is publishing a
// different admission state than this keeper currently computes.
//
// It exists because "what I last published" is process-local while the registry
// entry is shared: the server and the proof daemon each remember only their own
// writes, so one can publish a closure the other never learns about and never
// corrects. Asking the registry removes the guess.
//
// Any failure to read answers false. An unreachable registry must not force a
// publish storm, and the ordinary interval-based sync still runs underneath.
func registryDisagreesWithAdmission(cfg ServerConfig, closed bool) bool {
	if cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" || cfg.RPCURL == "" {
		return false
	}
	raw, err := os.ReadFile(cfg.VKRegistryABIPath)
	if err != nil {
		return false
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	abiJSON := raw
	if json.Unmarshal(raw, &artifact) == nil && len(artifact.ABI) > 2 {
		abiJSON = artifact.ABI
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		return false
	}
	status := readRegistryAdmissionStatus(
		cfg, parsedABI,
		common.HexToAddress(cfg.VKRegistryContract),
		common.HexToAddress(cfg.VKAddress),
	)
	if !status.Supported {
		return false
	}
	return status.Closed != closed
}

func readRegistryAdmissionStatus(cfg ServerConfig, parsedABI abi.ABI, toAddr, fromAddr common.Address) registryAdmissionStatus {
	if !hasRegistryMethod(parsedABI, "getAdmissionStatus") {
		return registryAdmissionStatus{Supported: false}
	}
	data, err := parsedABI.Pack("getAdmissionStatus", fromAddr)
	if err != nil {
		return registryAdmissionStatus{Supported: false}
	}
	callResult, err := rpcCall(cfg.RPCURL, "eth_call", []any{
		map[string]string{"to": toAddr.Hex(), "data": "0x" + hex.EncodeToString(data)},
		"latest",
	})
	if err != nil {
		return registryAdmissionStatus{Supported: false}
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(callResult, "0x"))
	if err != nil || len(raw) < 96 {
		return registryAdmissionStatus{Supported: false}
	}
	closed := len(raw) >= 32 && raw[31] == 1
	free := new(big.Int).SetBytes(raw[64:96]).Uint64()
	return registryAdmissionStatus{Closed: closed, FreeBytes: free, Supported: true}
}

func admissionClosureReasonCode(reason string) uint8 {
	switch reason {
	case "":
		return 0
	case AdmissionClosureCertifiedInsufficient:
		return 1
	case AdmissionClosureBacklogUnsafe:
		return 2
	case AdmissionClosureOldestDirtyHardLag:
		return 3
	case AdmissionClosureStorageOverload:
		return 4
	case AdmissionClosureProofUnavailable:
		return 5
	case AdmissionClosureRecoveryDisagreement:
		return 6
	case AdmissionClosureChainUnavailable:
		return 7
	case AdmissionClosureReservationUnavailable:
		return 8
	default:
		return 6
	}
}

func syncAdmissionStatusOnRegistry(cfg ServerConfig, state AdmissionState) bool {
	vkRegMu.Lock()
	defer vkRegMu.Unlock()
	closed := state.Closed
	freeBytes := state.SafeAllocatable

	if cfg.VKRegistryContract == "" || cfg.VKRegistryABIPath == "" || cfg.VKPrivKeyHex == "" ||
		cfg.RPCURL == "" || cfg.ChainID == 0 {
		log.Printf("[vk_adm] sync skipped enabled=%v registry=%v abi=%v key=%v rpc=%v chainId=%d",
			cfg.SyncAdmissionToRegistry, cfg.VKRegistryContract != "", cfg.VKRegistryABIPath != "",
			cfg.VKPrivKeyHex != "", cfg.RPCURL != "", cfg.ChainID)
		return false
	}

	raw, err := os.ReadFile(cfg.VKRegistryABIPath)
	if err != nil {
		log.Printf("[vk_adm] read ABI file: %v", err)
		return false
	}
	var artifact struct {
		ABI json.RawMessage `json:"abi"`
	}
	abiJSON := raw
	if json.Unmarshal(raw, &artifact) == nil && len(artifact.ABI) > 2 {
		abiJSON = artifact.ABI
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		log.Printf("[vk_adm] parse ABI: %v", err)
		return false
	}
	if !hasRegistryMethod(parsedABI, "updateAdmissionStatus") {
		log.Printf("[vk_adm] VaultKeeperRegistry ABI missing updateAdmissionStatus")
		return false
	}

	privKey, err := ParseVKPrivKey(cfg.VKPrivKeyHex)
	if err != nil {
		log.Printf("[vk_adm] invalid private key: %v", err)
		return false
	}
	fromAddr := common.HexToAddress(cfg.VKAddress)
	toAddr := common.HexToAddress(cfg.VKRegistryContract)

	useV2 := hasRegistryMethod(parsedABI, "updateAdmissionStatusV2") && state.CertificationObservationBlock > 0
	current := readRegistryAdmissionStatus(cfg, parsedABI, toAddr, fromAddr)
	if !useV2 && current.Supported && current.Closed == closed {
		reported := uint64(0)
		if freeBytes > 0 {
			reported = uint64(freeBytes)
		}
		if current.FreeBytes == reported {
			return true
		}
	}

	reported := uint64(0)
	if freeBytes > 0 {
		reported = uint64(freeBytes)
	}
	method := "updateAdmissionStatus"
	var calldata []byte
	if useV2 {
		method = "updateAdmissionStatusV2"
		calldata, err = parsedABI.Pack(method, closed, reported,
			admissionClosureReasonCode(state.ClosureReason), state.CertificationObservationBlock)
	} else {
		calldata, err = parsedABI.Pack(method, closed, reported)
	}
	if err != nil {
		log.Printf("[vk_adm] pack %s: %v", method, err)
		return false
	}

	accountLock, err := acquireAccountTxLock(fromAddr.Hex())
	if err != nil {
		log.Printf("[vk_adm] account transaction lock: %v", err)
		return false
	}
	defer accountLock.Release()

	nonce, err := rpcGetTransactionCount(cfg.RPCURL, fromAddr.Hex())
	if err != nil {
		log.Printf("[vk_adm] nonce: %v", err)
		return false
	}
	gasPrice := big.NewInt(cfg.FixedGasPriceWei)
	if gasPrice.Sign() <= 0 {
		gasPrice = big.NewInt(1_000_000)
	}
	gasLimit := uint64(250000)
	tx := types.NewTransaction(nonce, toAddr, big.NewInt(0), gasLimit, gasPrice, calldata)
	signer := types.NewEIP155Signer(big.NewInt(cfg.ChainID))
	signedTx, err := types.SignTx(tx, signer, privKey)
	if err != nil {
		log.Printf("[vk_adm] sign tx: %v", err)
		return false
	}
	rawTx, err := signedTx.MarshalBinary()
	if err != nil {
		log.Printf("[vk_adm] marshal tx: %v", err)
		return false
	}
	txHash, err := rpcSendRawTransaction(cfg.RPCURL, rawTx)
	if err != nil {
		log.Printf("[vk_adm] send tx: %v", err)
		return false
	}
	if receipt, receiptErr := rpcWaitTransactionReceipt(cfg.RPCURL, txHash, 30*time.Second); receiptErr == nil && receipt != nil {
		logMinedTx("vk:VaultKeeperRegistry."+method, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(),
			"VaultKeeperRegistry", method, toAddr.Hex(), signedTx, receipt,
			map[string]any{"closed": closed, "safeAllocatable": reported,
				"closureReason": state.ClosureReason, "observationBlock": state.CertificationObservationBlock})
	} else {
		logSubmittedTx("vk:VaultKeeperRegistry."+method, cfg.RPCURL, cfg.ChainID, fromAddr.Hex(),
			"VaultKeeperRegistry", method, toAddr.Hex(), signedTx, txHash,
			map[string]any{"closed": closed, "safeAllocatable": reported,
				"closureReason": state.ClosureReason, "observationBlock": state.CertificationObservationBlock})
	}
	log.Printf("[vk_adm] admission status synced closed=%v safe=%d reason=%s block=%d tx=%s",
		closed, reported, state.ClosureReason, state.CertificationObservationBlock, txHash)
	logAdmissionTransition(closed, reported, state.ClosureReason, state.ReasonDetail)
	return true
}

// lastSyncedAdmissionClosed remembers the admission state this process last published, so a
// genuine open<->closed transition can be announced separately from the routine sync line.
// nil means "nothing published yet in this process".
var lastSyncedAdmissionClosed *bool

// logAdmissionTransition prints a distinct, human-legible line ONLY when admission actually
// changes direction. Admission decides whether this vault keeper can accept new data, but the
// routine sync line above prints on every publish and renders a reopen as "closed=false
// reason=" — an empty field that reads like routine chatter at roughly one line in a hundred.
// Operators watching a live vault keeper window need the transition to stand out; machine
// consumers keep parsing the unchanged sync line above.
//
// closureDetail is what makes a closure actionable. A single reason code covers several
// distinct causes — proof_subsystem_unavailable alone means "startup barrier still shut",
// "backlog observation is stale" or "backlog metrics are invalid", which call for entirely
// different responses. The detail is computed at every closure and was, until now, discarded,
// leaving those causes indistinguishable in the log.
func logAdmissionTransition(closed bool, safeAllocatable uint64, closureReason, closureDetail string) {
	if lastSyncedAdmissionClosed != nil && *lastSyncedAdmissionClosed == closed {
		return
	}
	first := lastSyncedAdmissionClosed == nil
	lastSyncedAdmissionClosed = &closed
	detail := admissionDetailSuffix(closureDetail)
	switch {
	case closed && first:
		log.Printf("[vk_adm] ADMISSION CLOSED (initial)  reason=%s safe=%d%s", closureReason, safeAllocatable, detail)
	case closed:
		log.Printf("[vk_adm] ADMISSION CLOSED  reason=%s safe=%d%s", closureReason, safeAllocatable, detail)
	case first:
		log.Printf("[vk_adm] ADMISSION OPEN (initial)  safe=%d", safeAllocatable)
	default:
		log.Printf("[vk_adm] ADMISSION REOPENED  safe=%d", safeAllocatable)
	}
}

// admissionDetailSuffix renders a closure detail as a trailing ` detail="..."` field, or an
// empty string when there is nothing to add. Details are assembled from error strings, so they
// are folded onto one line and capped: a transition line that wraps or floods the window
// defeats the point of printing it separately.
func admissionDetailSuffix(closureDetail string) string {
	detail := strings.TrimSpace(strings.Join(strings.Fields(closureDetail), " "))
	if detail == "" {
		return ""
	}
	return fmt.Sprintf(" detail=%q", truncate(detail, 200))
}

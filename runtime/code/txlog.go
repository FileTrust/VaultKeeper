package main

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

var txLogPath string

func setTransactionLogPath(path string) {
	txLogPath = path
}

func appendTransactionLog(payload map[string]any) {
	if txLogPath == "" {
		return
	}
	payload["facility"] = "vault_keeper"
	payload["source"] = "VK"
	// Emit host-local timezone timestamp for operator-friendly correlation.
	payload["timestamp"] = time.Now().Format(time.RFC3339)
	if _, ok := payload["network"]; !ok {
		payload["network"] = ""
	}
	if err := os.MkdirAll(filepath.Dir(txLogPath), 0755); err != nil {
		return
	}
	line, err := json.Marshal(payload)
	if err != nil {
		return
	}
	f, err := os.OpenFile(txLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func logEthCall(tag, rpcURL string, chainID int64, contractName, functionName, contractAddress, actorAddress, status string, details map[string]any) {
	payload := map[string]any{
		"tag":                     tag,
		"transaction_kind":        "eth_call",
		"chain_id":                stringInt(chainID),
		"rpc_url":                 rpcURL,
		"actor_address":           actorAddress,
		"contract_name":           contractName,
		"function_name":           functionName,
		"contract_address":        contractAddress,
		"to_address":              contractAddress,
		"value_wei":               "0",
		"transaction_hash":        "",
		"block_number":            "",
		"status":                  status,
		"gas_used":                "0",
		"gas_price_wei":           "0",
		"effective_gas_price_wei": "0",
		"total_cost_wei":          "0",
		"total_cost_eth":          "0",
	}
	for k, v := range details {
		payload[k] = v
	}
	appendTransactionLog(payload)
}

func logSubmittedTx(tag, rpcURL string, chainID int64, actorAddress, contractName, functionName, contractAddress string, tx *types.Transaction, txHash string, details map[string]any) {
	value := "0"
	gasPrice := "0"
	gasLimit := "0"
	estimatedMaxCost := "0"
	if tx != nil {
		value = tx.Value().String()
		gasPrice = tx.GasPrice().String()
		gasLimit = stringUint(tx.Gas())
		estimatedMaxCost = new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasPrice()).String()
	}
	payload := map[string]any{
		"tag":                     tag,
		"transaction_kind":        "contract_transaction_submitted",
		"chain_id":                stringInt(chainID),
		"rpc_url":                 rpcURL,
		"actor_address":           actorAddress,
		"contract_name":           contractName,
		"function_name":           functionName,
		"contract_address":        contractAddress,
		"to_address":              contractAddress,
		"value_wei":               value,
		"transaction_hash":        txHash,
		"block_number":            "",
		"status":                  "submitted",
		"gas_used":                "0",
		"gas_limit":               gasLimit,
		"gas_price_wei":           gasPrice,
		"effective_gas_price_wei": gasPrice,
		"total_cost_wei":          "0",
		"total_cost_eth":          "0",
		"estimated_max_cost_wei":  estimatedMaxCost,
	}
	for k, v := range details {
		payload[k] = v
	}
	appendTransactionLog(payload)
}

func logMinedTx(tag, rpcURL string, chainID int64, actorAddress, contractName, functionName, contractAddress string, tx *types.Transaction, receipt *rpcReceipt, details map[string]any) {
	if receipt == nil {
		return
	}
	value := "0"
	gasPrice := "0"
	if tx != nil {
		value = tx.Value().String()
		gasPrice = tx.GasPrice().String()
	}
	effectiveGasPrice := decimalFromHex(receipt.EffectiveGasPrice)
	if effectiveGasPrice == "0" {
		effectiveGasPrice = gasPrice
	}
	gasUsed := decimalFromHex(receipt.GasUsed)
	totalCostWei := "0"
	if gu, ok := new(big.Int).SetString(gasUsed, 10); ok {
		if gp, ok := new(big.Int).SetString(effectiveGasPrice, 10); ok {
			totalCostWei = new(big.Int).Mul(gu, gp).String()
		}
	}
	payload := map[string]any{
		"tag":                     tag,
		"transaction_kind":        "contract_transaction",
		"chain_id":                stringInt(chainID),
		"rpc_url":                 rpcURL,
		"actor_address":           actorAddress,
		"contract_name":           contractName,
		"function_name":           functionName,
		"contract_address":        contractAddress,
		"to_address":              contractAddress,
		"value_wei":               value,
		"transaction_hash":        receipt.TransactionHash,
		"block_number":            decimalFromHex(receipt.BlockNumber),
		"status":                  decimalFromHex(receipt.Status),
		"gas_used":                gasUsed,
		"gas_price_wei":           gasPrice,
		"effective_gas_price_wei": effectiveGasPrice,
		"total_cost_wei":          totalCostWei,
		"total_cost_eth":          weiToEthDecimal(totalCostWei),
	}
	for k, v := range details {
		payload[k] = v
	}
	appendTransactionLog(payload)
}

func decimalFromHex(value string) string {
	clean := strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if clean == "" {
		return "0"
	}
	n, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		return "0"
	}
	return n.String()
}

func weiToEthDecimal(value string) string {
	wei, ok := new(big.Int).SetString(value, 10)
	if !ok || wei.Sign() == 0 {
		return "0"
	}
	scale := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	whole := new(big.Int).Quo(wei, scale)
	frac := new(big.Int).Mod(wei, scale).Text(10)
	frac = strings.TrimRight(strings.Repeat("0", 18-len(frac))+frac, "0")
	if frac == "" {
		return whole.String()
	}
	return whole.String() + "." + frac
}

func stringInt(v int64) string {
	return big.NewInt(v).String()
}

func stringUint(v uint64) string {
	return new(big.Int).SetUint64(v).String()
}

func statusFromErr(err error) string {
	if err != nil {
		return "failed"
	}
	return "success"
}

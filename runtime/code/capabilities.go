package main

import (
	"encoding/json"
	"os"
	"strings"
)

// ClientCapabilities names what this VaultMesh build relays between a keeper and a
// data owner. The data owner's app asks (`--mode capabilities`) before it requests a
// quote: once the refund contracts need the escrow's link nonce, a build that drops
// it from the keeper's reply must not start an escrow the owner could not refund.
// A build from before this file does not know the question and exits with an error.
type ClientCapabilities struct {
	Schema         int  `json:"schema"`
	QuoteLinkNonce bool `json:"quoteLinkNonce"`
}

func clientCapabilities() ClientCapabilities {
	return ClientCapabilities{Schema: 1, QuoteLinkNonce: true}
}

// The question is answered before flags, keys or configuration are read, so any
// install can be asked, configured or not.
func init() {
	if requestedMode(os.Args[1:]) != "capabilities" {
		return
	}
	_ = json.NewEncoder(os.Stdout).Encode(clientCapabilities())
	os.Exit(0)
}

func requestedMode(args []string) string {
	for i, arg := range args {
		switch {
		case arg == "--mode" || arg == "-mode":
			if i+1 < len(args) {
				return args[i+1]
			}
		case strings.HasPrefix(arg, "--mode=") || strings.HasPrefix(arg, "-mode="):
			return arg[strings.Index(arg, "=")+1:]
		}
	}
	return ""
}

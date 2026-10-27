//go:build filetrust_runtime

package main

import "fmt"

func runSetupMode(partition bool, keys, partitionKeys, config string) error {
	return fmt.Errorf("setup generation is disabled in the download-only Vaultkeeper runtime; install a signed proof bundle")
}

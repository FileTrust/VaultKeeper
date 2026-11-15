package main

// terminalProofExpiration reserves a bounded physical proof envelope. It never
// changes PieceMeta.ServiceEnd, the registration term, escrow term or price.
// A proof earlier in the maturity round may already exist (and be idempotent),
// so the following full round must remain available for the regular scheduler.
func terminalProofExpiration(cfg ServerConfig, serviceEnd int64) int64 {
	if cfg.VKEscrowContract == "" || serviceEnd <= 0 || cfg.ProofPeriodSeconds <= 0 {
		return serviceEnd
	}
	period := cfg.ProofPeriodSeconds
	bound := int64(cfg.ProofDeadlineConservativeBoundSeconds)
	if bound <= 0 {
		bound = DefaultProofDeadlineConservativeBoundSeconds
	}
	rounds := serviceEnd / period
	if serviceEnd%period != 0 {
		rounds++
	}
	// Defend against malformed local configuration without overflowing expiry.
	const max = int64(^uint64(0) >> 1)
	if rounds >= max/period-1 || bound > max-(rounds+1)*period {
		return serviceEnd
	}
	return (rounds+1)*period + bound
}

// Capacity-only sector creation continues to use newSectorWithID unchanged.
func newDataSectorWithID(cfg ServerConfig, serviceEnd int64, sectorID string) SectorMeta {
	sector := newSectorWithID(cfg, serviceEnd, sectorID)
	if until := terminalProofExpiration(cfg, serviceEnd); sector.Expiration < until {
		sector.Expiration = until
	}
	return sector
}

package admin

import "time"

// Long-term observation and legacy failover keep their existing strict receipt
// clock. Investigation may separately verify transport delay from completion IDs.
func dispatchEvidenceFollows(newer, older DispatchHistorySample, c dispatchSplitCandidate) bool {
	if older.Sequence >= newer.Sequence || older.ReportedAt > newer.ReportedAt {
		return false
	}
	const timestampFloor int64 = 100000000000000000
	if newer.Sequence >= timestampFloor || older.Sequence >= timestampFloor {
		if newer.Sequence < timestampFloor || older.Sequence < timestampFloor {
			return false
		}
		maxGap := c.Interval + (c.Timeout+999)/1000 + 5
		return newer.Sequence-older.Sequence <= maxGap*int64(time.Second) && newer.ReportedAt-older.ReportedAt <= maxGap
	}
	return newer.Sequence-older.Sequence == 1
}

// Probe result IDs contain Unix nanoseconds. They establish ordering, not a
// consecutive counter. Bound the completion gap to one configured check cycle
// plus a small scheduling allowance. Server receipts may lag by one extra check
// interval only when timestamp IDs independently prove completion continuity.
// Neither a missed check nor a long reporting outage is hidden by this allowance.
// Freshness and elapsed completion time are also checked by callers.
// Keep support for consecutive counter IDs used by older integrations.
func investigationEvidenceFollows(newer, older DispatchHistorySample, c dispatchSplitCandidate) bool {
	if older.Sequence >= newer.Sequence || older.ReportedAt > newer.ReportedAt {
		return false
	}
	maxGap := c.Interval + (c.Timeout+999)/1000 + 5
	const timestampFloor int64 = 100000000000000000
	if newer.Sequence >= timestampFloor || older.Sequence >= timestampFloor {
		if newer.Sequence < timestampFloor || older.Sequence < timestampFloor {
			return false
		}
		return newer.Sequence-older.Sequence <= maxGap*int64(time.Second) && newer.ReportedAt-older.ReportedAt <= maxGap+c.Interval
	}
	// Counter IDs contain no independent completion clock, so they cannot
	// distinguish transport delay from a missing check.
	return newer.Sequence-older.Sequence == 1 && newer.ReportedAt-older.ReportedAt <= maxGap
}

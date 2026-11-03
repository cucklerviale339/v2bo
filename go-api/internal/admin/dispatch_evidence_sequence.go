package admin

import "time"

// Probe result IDs contain Unix nanoseconds. They establish ordering, not a
// consecutive counter. Bound the completion gap to one configured check cycle
// plus a small scheduling allowance. Reject excessive completion or receipt
// gaps even when queued results arrive together. Freshness is also checked by
// the caller against the latest server receipt time.
// Keep support for consecutive counter IDs used by older integrations.
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

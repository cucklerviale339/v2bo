package admin

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Receipt ownership, the observed outage and permission to automate are separate
// facts. A missing observation can suspend automation without erasing receipts.
type investigationIncident struct {
	First, LastSuccess  int64
	Baseline, Uncertain bool
	Sequence, Reported  int64
}

func investigationIncidentFrom(samples []DispatchHistorySample, c dispatchSplitCandidate, epoch, confirmed int64, saved investigationIncident) investigationIncident {
	out := investigationIncident{}
	if len(samples) == 0 {
		if saved.Reported >= epoch && saved.First >= epoch && saved.First > 0 {
			out = saved
			out.Uncertain = true
		}
		return out
	}
	maxGap := c.Interval + (c.Timeout+999)/1000 + 5
	// Human confirmation starts a receipt round; only a real successful probe
	// observation establishes the baseline needed for automatic execution.
	savedSeen := false
	successSeen := false
	for i := len(samples) - 1; i >= 0; i-- {
		x := samples[i]
		if x.Sequence == saved.Sequence && x.ReportedAt == saved.Reported {
			savedSeen = true
		}
		if x.Version != c.Version || x.RunID != c.RunID || x.ReportedAt < epoch || x.ReportedAt > c.Reported {
			out.Uncertain = true
			continue
		}
		if x.UnverifiedRestartBefore || (i+1 < len(samples) && (!dispatchEvidenceFollows(x, samples[i+1], c) || x.ReportedAt-samples[i+1].ReportedAt > maxGap) && !x.RecordedRestartBefore) {
			out.Uncertain = true
		}
		if x.Success {
			out.First = 0
			out.LastSuccess = x.ReportedAt
			out.Baseline = true
			out.Uncertain = false
			successSeen = true
		} else {
			if out.First == 0 {
				out.First = x.ReportedAt
			}
		}
		out.Sequence = x.Sequence
		out.Reported = x.ReportedAt
	}
	// Retain a missing anchor for manual use, but only its exact observed sample
	// may carry an automatic baseline. Recovery supersedes an earlier anchor.
	if !successSeen && saved.First >= epoch && saved.First > 0 && saved.First <= out.First && saved.Reported <= c.Reported {
		out.First = saved.First
		out.LastSuccess = saved.LastSuccess
		out.Baseline = out.Baseline || (savedSeen && saved.Baseline)
		out.Uncertain = out.Uncertain || saved.Uncertain || !savedSeen
	}
	return out
}

func loadInvestigationIncident(ctx context.Context, tx *sql.Tx, g InvestigationGroup, p investigationProbe, samples []DispatchHistorySample) (investigationIncident, error) {
	var saved investigationIncident
	err := tx.QueryRowContext(ctx, `SELECT first_failure_at,last_success_at,baseline,uncertain,sequence,reported_at FROM v2_dispatch_investigation_incident WHERE group_id=$1 AND generation=$2 AND probe_id=$3 AND version=$4`, g.ID, g.Generation, p.ProbeID, p.Version).Scan(&saved.First, &saved.LastSuccess, &saved.Baseline, &saved.Uncertain, &saved.Sequence, &saved.Reported)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return saved, err
	}
	incident := investigationIncidentFrom(samples, p.dispatchSplitCandidate, g.EpochAt, g.ConfirmedAt, saved)
	if len(samples) == 0 {
		return incident, nil
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_investigation_incident(group_id,generation,probe_id,version,first_failure_at,last_success_at,baseline,uncertain,sequence,reported_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(group_id,generation,probe_id,version) DO UPDATE SET first_failure_at=EXCLUDED.first_failure_at,last_success_at=EXCLUDED.last_success_at,baseline=EXCLUDED.baseline,uncertain=EXCLUDED.uncertain,sequence=EXCLUDED.sequence,reported_at=EXCLUDED.reported_at`, g.ID, g.Generation, p.ProbeID, p.Version, incident.First, incident.LastSuccess, incident.Baseline, incident.Uncertain, incident.Sequence, incident.Reported)
	return incident, err
}

// Only observed completion and receipt intervals count toward automation.
// A restart, gap or success starts a fresh verification window. Error text
// describes a failed result and never changes its success/failure meaning.
func investigationFailureWindow(samples []DispatchHistorySample, c dispatchSplitCandidate, now, duration int64) bool {
	if c.Success || !dispatchSplitFresh(c, now) || len(samples) < 2 || samples[0].Sequence != c.Sequence || samples[0].ReportedAt != c.Reported {
		return false
	}
	for i, x := range samples {
		if x.Version != c.Version || x.RunID != c.RunID || x.Success {
			return false
		}
		if i > 0 && (samples[i-1].RecordedRestartBefore || samples[i-1].UnverifiedRestartBefore || !dispatchEvidenceFollows(samples[i-1], x, c) || samples[i-1].ReportedAt-x.ReportedAt > c.Interval+(c.Timeout+999)/1000+5) {
			return false
		}
		if i > 0 && c.Reported-x.ReportedAt >= duration {
			// Timestamp IDs describe when the probe completed the check. A
			// buffered burst cannot manufacture ten minutes of actual checks.
			if c.Sequence >= 100000000000000000 && c.Sequence-x.Sequence < duration*int64(time.Second) {
				continue
			}
			return true
		}
	}
	return false
}

// Manual execution is an administrator's decision, not an automatic diagnosis.
// It takes an immutable cutoff before allocating IPs and reuses that exact
// snapshot at commit, without inventing success or changing the receipt round.
func (s *DBService) manualInvestigationEvidence(ctx context.Context, tx *sql.Tx, g InvestigationGroup, probes []investigationProbe) (investigationEvidence, error) {
	out := investigationEvidence{Mode: "manual", CutoffSource: "manual_snapshot", First: time.Now().Unix(), Controls: map[int64][]string{}, Warnings: []string{"人工执行，未使用自动故障等待、正常对照和自动限频"}}
	for _, p := range probes {
		samples, err := investigationSamples(ctx, tx, p.dispatchSplitCandidate, g.EpochAt)
		if err != nil {
			return out, err
		}
		// A human can act while the first post-restart state is still pending.
		// The most recent stored observation remains evidence, not a fresh probe.
		if len(samples) > 0 && p.Reported < samples[0].ReportedAt {
			p.Reported = samples[0].ReportedAt
			p.Sequence = samples[0].Sequence
		}
		incident, err := loadInvestigationIncident(ctx, tx, g, p, samples)
		if err != nil {
			return out, err
		}
		out.Probes = append(out.Probes, p.ProbeID)
		if incident.First >= g.EpochAt && incident.First <= out.First {
			out.First = incident.First
			out.CutoffSource = "first_observed_failure"
			if incident.Baseline && !incident.Uncertain {
				out.CutoffSource = "established_incident"
			}
		}
	}
	return out, nil
}

package admin

import (
	"context"
	"database/sql"
	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
	"time"
)

// Manual execution alone never means a confirmed fault. Persist the healthy
// independent sibling groups while actual dispatch and probe evidence exist.
func (s *DBService) investigationRiskNarrowing(ctx context.Context, tx *sql.Tx, g InvestigationGroup, groups []InvestigationGroup, entries []usersvc.DispatchEntry, evidence investigationEvidence, accounts *investigationDispatchAccounts) (*postgres.DispatchRiskNarrowing, error) {
	if accounts == nil {
		accounts = newInvestigationDispatchAccounts(tx)
	}
	out := &postgres.DispatchRiskNarrowing{HealthyGroups: []int64{}}
	_, probes, fresh, err := investigationProbeConfig(ctx, tx, g.MonitorID)
	if err != nil || !fresh {
		return out, err
	}
	verified, reason, err := s.investigationEvidenceWithDuration(ctx, tx, g, probes, entries, 600)
	if err != nil || reason != "" || verified.ReceiptsIncomplete || verified.First != evidence.First {
		return out, err
	}
	out.Confirmed = true
	actual := map[string]bool{}
	for _, entry := range entries {
		actual[entry.Host] = true
	}
	for _, other := range groups {
		if other.ID == g.ID || other.Host == g.Host || !actual[other.Host] || len(other.UserIDs) == 0 {
			continue
		}
		outside, e := hasOutsideDispatch(ctx, tx, other, entries, accounts)
		if e != nil {
			return nil, e
		}
		if outside {
			continue
		}
		key, states, ready, e := investigationProbeConfig(ctx, tx, other.MonitorID)
		if e != nil {
			return nil, e
		}
		if !ready || key != other.ConfigKey {
			continue
		}
		healthy := true
		for _, p := range states {
			if !p.Success || s.dispatchProbeResetBlocked(p.ProbeID) {
				healthy = false
				break
			}
			for _, source := range probes {
				if source.ProbeID == p.ProbeID && source.ResolvedIP != "" && source.ResolvedIP == p.ResolvedIP {
					healthy = false
				}
			}
			samples, e := investigationSamples(ctx, tx, p.dispatchSplitCandidate, verified.WindowFrom-max(defaultProbeOfflineSec, 2*(p.Interval+(p.Timeout+999)/1000)))
			if e != nil {
				return nil, e
			}
			healthy = healthy && investigationControlSpan(samples, p.dispatchSplitCandidate, verified.WindowFrom, time.Now().Unix())
		}
		if healthy {
			out.HealthyGroups = append(out.HealthyGroups, other.ID)
		}
	}
	return out, nil
}

const investigationRiskBlocked = `(EXISTS(SELECT 1 FROM v2_dispatch_risk_member rm JOIN v2_dispatch_risk_case rc ON rc.event_id=rm.event_id WHERE rm.user_id=m.user_id AND rc.resolved_event_id=0 AND rm.cleared_event_id=0)
OR EXISTS(SELECT 1 FROM v2_dispatch_investigation_event proof WHERE proof.payload->'confirmation'->>'version'='1' AND proof.payload->'confirmation'->>'user_id'=m.user_id::text))`

const investigationRiskReleasedAt = `COALESCE((SELECT max(CASE WHEN rm.cleared_event_id>0 THEN rm.cleared_at ELSE rc.resolved_at END) FROM v2_dispatch_risk_member rm JOIN v2_dispatch_risk_case rc ON rc.event_id=rm.event_id WHERE rm.user_id=m.user_id),0)`

const investigationPromotionHold = `EXISTS(SELECT 1 FROM v2_dispatch_risk_member rm
JOIN v2_dispatch_risk_case rc ON rc.event_id=rm.event_id
JOIN v2_dispatch_investigation_event e ON e.id=rc.event_id
WHERE rm.user_id=m.user_id AND rc.resolved_event_id=0 AND rm.cleared_event_id=0
AND e.kind='stage_corrected' AND e.payload->>'promotion_hold'='true')`

// A correction hold follows concrete people across edits/moves. It is not a
// timer, and another branch's failure cannot release it.
func investigationPromotionHeld(ctx context.Context, tx *sql.Tx, group int64) (bool, error) {
	var held bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_member m WHERE m.group_id=$1 AND `+investigationPromotionHold+`)`, group).Scan(&held)
	return held, err
}

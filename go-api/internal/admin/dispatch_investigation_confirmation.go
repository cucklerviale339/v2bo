package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	usersvc "forest/go-api/internal/user"
)

// A partition's size is never evidence. This proof belongs to the failed
// entrance round, before any partition or address allocation is performed.
type investigationConfirmationProof struct {
	Version        int                   `json:"version"`
	UserID         int64                 `json:"user_id"`
	GroupID        int64                 `json:"source_group_id"`
	Generation     int64                 `json:"generation"`
	Host           string                `json:"host"`
	MonitorID      int64                 `json:"monitor_id"`
	ConfigKey      string                `json:"config_key"`
	FirstPullAt    int64                 `json:"first_pull_at"`
	HealthyAt      map[int64]int64       `json:"healthy_at"`
	EpochAt        int64                 `json:"epoch_at"`
	FirstFailureAt int64                 `json:"first_failure_at"`
	VerifiedAt     int64                 `json:"verified_at"`
	RelatedRoots   []int64               `json:"related_roots"`
	Evidence       investigationEvidence `json:"evidence"`
}

func (s *DBService) investigationConfirmation(ctx context.Context, tx *sql.Tx, g InvestigationGroup, evidence investigationEvidence, entries []usersvc.DispatchEntry, pulled map[int64]bool) (*investigationConfirmationProof, error) {
	if g.Policy != "smart" || g.ReadyAt == 0 || evidence.First <= g.ReadyAt || evidence.ReceiptsIncomplete || len(pulled) != 1 || evidence.Mode == "observation_repair" {
		return nil, nil
	}
	var id int64
	for user := range pulled {
		id = user
	}
	inside := false
	for _, user := range investigationGroupIDs(g) {
		inside = inside || user == id
	}
	if !inside {
		return nil, nil
	}
	var count, recipient, firstPull int64
	if err := tx.QueryRowContext(ctx, `SELECT count(DISTINCT user_id),COALESCE(min(user_id),0),COALESCE(min(delivered_at),0) FROM (
SELECT user_id,delivered_at FROM v2_dispatch_investigation_delivery WHERE group_id=$1 AND generation=$2
UNION ALL SELECT user_id,delivered_at FROM v2_dispatch_investigation_delivery_recent WHERE group_id=$1 AND generation=$2
) d WHERE delivered_at>=$3 AND delivered_at<$4`, g.ID, g.Generation, g.EpochAt, evidence.First).Scan(&count, &recipient, &firstPull); err != nil {
		return nil, err
	}
	if count != 1 || recipient != id {
		return nil, nil
	}
	// Aggregated exposure cannot prove when an outside user pulled relative to
	// the cutoff. Never turn that uncertainty (including deleted users) into a
	// sole-recipient accusation. A shared host is not an isolated group round.
	outside, err := hasOutsideExposure(ctx, tx, g)
	if err != nil || outside {
		return nil, err
	}
	outside, err = hasOutsideDispatch(ctx, tx, g, entries)
	if err != nil || outside {
		return nil, err
	}
	key, probes, fresh, err := investigationProbeConfig(ctx, tx, g.MonitorID)
	if err != nil || !fresh || key != g.ConfigKey {
		return nil, err
	}
	if firstPull < g.ReadyAt || g.ConfirmedAt > 0 {
		// An administrator's confirmation is not a successful probe. Nor can
		// success after the user's pull retrospectively prove a healthy issue.
		for _, p := range probes {
			samples, e := investigationSamples(ctx, tx, p.dispatchSplitCandidate, g.EpochAt)
			if e != nil {
				return nil, e
			}
			healthyBeforePull := false
			for _, x := range samples {
				healthyBeforePull = healthyBeforePull || (x.Success && x.ReportedAt <= firstPull)
			}
			if !healthyBeforePull {
				return nil, nil
			}
		}
	}
	// Manual execution can perform a partition immediately, but cannot grant
	// a confirmed label by skipping the healthy baseline or fault verification.
	verified, reason, err := s.investigationEvidenceWithDuration(ctx, tx, g, probes, entries, 600)
	if err != nil || reason != "" || verified.ReceiptsIncomplete || verified.First != evidence.First {
		return nil, err
	}
	var armed int64
	if err := tx.QueryRowContext(ctx, `SELECT armed_at FROM v2_dispatch_investigation_settings WHERE id=1`).Scan(&armed); err != nil {
		return nil, err
	}
	if verified.First < armed {
		return nil, nil
	}
	healthyAt := map[int64]int64{}
	for _, p := range probes {
		var at int64
		if err := tx.QueryRowContext(ctx, `SELECT last_success_at FROM v2_dispatch_investigation_incident WHERE group_id=$1 AND generation=$2 AND probe_id=$3 AND version=$4 AND baseline AND NOT uncertain`, g.ID, g.Generation, p.ProbeID, p.Version).Scan(&at); err != nil {
			return nil, err
		}
		if at < g.EpochAt || at >= evidence.First {
			return nil, nil
		}
		healthyAt[p.ProbeID] = at
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(jsonb_agg(DISTINCT root_id),'[]') FROM (SELECT $3::bigint AS root_id UNION SELECT root_id FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id=$2) r`, g.ID, id, g.RootID).Scan(&raw); err != nil {
		return nil, err
	}
	roots := []int64{}
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, err
	}
	return &investigationConfirmationProof{Version: 1, UserID: id, GroupID: g.ID, Generation: g.Generation, Host: g.Host, MonitorID: g.MonitorID, ConfigKey: g.ConfigKey, FirstPullAt: firstPull, HealthyAt: healthyAt, EpochAt: g.EpochAt, FirstFailureAt: verified.First, VerifiedAt: time.Now().Unix(), RelatedRoots: roots, Evidence: verified}, nil
}

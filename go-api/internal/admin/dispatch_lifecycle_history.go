package admin

import (
	"context"
	"database/sql"
	"encoding/json"
)

// Legacy policy is action-based: an unchanged round without screening or a
// manual edit counts as normal observation, even after raw samples expire.
// This is historical business credit, not reconstructed probe continuity.
// New live evidence continues to use checkpoints and pauses reporting gaps.
func legacyObservationStart(g InvestigationGroup, settings InvestigationSettings, created, lastAction int64) int64 {
	return max(max(g.EpochAt, settings.ArmedAt), max(created, lastAction))
}

func (s *DBService) importNormalHistory(ctx context.Context, tx *sql.Tx, g *InvestigationGroup, settings InvestigationSettings, probes []investigationProbe) (bool, error) {
	// Existing durable progress (including an earlier release of the lifecycle)
	// is authoritative. Never overwrite it with shorter raw-history retention.
	bootstrap := g.NormalSince == 0
	var boundary int64
	if err := tx.QueryRowContext(ctx, `SELECT GREATEST(g.created_at,COALESCE((SELECT max(e.created_at) FROM v2_dispatch_investigation_event e
WHERE e.group_id=g.id AND e.kind IN('edited','confirmed_entry','filtered','bisected','no_pulls','recovered','stable_promoted','whitelist_promoted','whitelist_failed_over','whitelist_bisected','whitelist_returned','global_released','members_admitted','members_moved')),0))
FROM v2_dispatch_investigation_group g WHERE g.id=$1`, g.ID).Scan(&boundary); err != nil {
		return false, err
	}
	boundary = legacyObservationStart(*g, settings, boundary, 0)
	if bootstrap {
		previous := map[int64]normalCheckpoint{}
		for _, p := range probes {
			if !p.Success || p.Host != g.Host || p.Reported < boundary {
				return false, nil
			}
			previous[p.ProbeID] = normalCheckpoint{p.Version, p.RunID, p.Sequence, p.Reported}
		}
		if len(previous) == 0 {
			return false, nil
		}
		g.NormalSince = boundary
		g.NormalCheckpoints, _ = json.Marshal(previous)
	}
	ids, _ := json.Marshal(investigationGroupIDs(*g))
	if bootstrap {
		// A receipt written after startup but before this worker pass can still
		// predate a subsequent manual edit. Only pulls within the accepted
		// action boundary may seed the imported personal timer.
		if _, err := tx.ExecContext(ctx, `DELETE FROM v2_dispatch_stability_receipt d USING v2_dispatch_investigation_member m
WHERE m.group_id=$1 AND m.origin_host=d.origin_host AND m.user_id=d.user_id AND d.host=$2
AND m.user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($3::jsonb))
AND d.last_at<=$5 AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_delivery x WHERE x.group_id=$1 AND x.generation=$4 AND x.user_id=m.user_id AND x.delivered_at BETWEEN $6 AND $5)
AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_delivery_recent x WHERE x.group_id=$1 AND x.generation=$4 AND x.user_id=m.user_id AND x.delivered_at BETWEEN $6 AND $5)`, g.ID, g.Host, string(ids), g.Generation, minimumProbeReport(probes), boundary); err != nil {
			return false, err
		}
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_stability_receipt(origin_host,user_id,host,first_at,last_at)
SELECT m.origin_host,m.user_id,$2,GREATEST(min(d.delivered_at),$5::bigint),max(d.delivered_at)
FROM v2_dispatch_investigation_member m JOIN v2_user u ON u.id=m.user_id
JOIN (SELECT user_id,delivered_at FROM v2_dispatch_investigation_delivery WHERE group_id=$1 AND generation=$3
UNION ALL SELECT user_id,delivered_at FROM v2_dispatch_investigation_delivery_recent WHERE group_id=$1 AND generation=$3) d ON d.user_id=m.user_id
WHERE m.group_id=$1 AND m.user_id IN(SELECT value::bigint FROM jsonb_array_elements_text($6::jsonb))
AND d.delivered_at>=$4 AND d.delivered_at<=$7
GROUP BY m.origin_host,m.user_id
ON CONFLICT(origin_host,user_id) DO UPDATE SET first_at=EXCLUDED.first_at,last_at=GREATEST(v2_dispatch_stability_receipt.last_at,EXCLUDED.last_at)
WHERE $8 AND v2_dispatch_stability_receipt.host=EXCLUDED.host AND v2_dispatch_stability_receipt.last_at<=$7`, g.ID, g.Host, g.Generation, boundary, g.NormalSince, string(ids), minimumProbeReport(probes), bootstrap)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_group SET normal_history_imported=TRUE,normal_since=$2,normal_checkpoints=$3 WHERE id=$1`, g.ID, g.NormalSince, string(g.NormalCheckpoints)); err != nil {
		return false, err
	}
	if err = investigationAudit(ctx, tx, g.RootID, g.ID, "observation_imported", 0, map[string]any{"host": g.Host, "generation": g.Generation, "normal_since": g.NormalSince, "legacy_boundary": boundary, "imported_receipts": count, "source": "unchanged_round_and_current_round_receipts", "existing_progress_preserved": !bootstrap}); err != nil {
		return false, err
	}
	g.NormalHistoryImported = true
	return true, nil
}

func minimumProbeReport(probes []investigationProbe) int64 {
	var at int64
	for _, p := range probes {
		if at == 0 || p.Reported < at {
			at = p.Reported
		}
	}
	return at
}

package subscribeguard

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var ErrMonitorUnavailable = errors.New("风险历史与 IP 情报未就绪，原订阅防护仍可用")

const monitorControlSchema = `
CREATE TABLE IF NOT EXISTS v2_subscribe_monitor_control (
 id SMALLINT PRIMARY KEY CHECK (id=1), ip_enabled BOOLEAN NOT NULL DEFAULT true,
 revision BIGINT NOT NULL DEFAULT 0, updated_by BIGINT NOT NULL DEFAULT 0,
 updated_at BIGINT NOT NULL DEFAULT 0, snapshot_next BIGINT NOT NULL DEFAULT 0,
 snapshot_at BIGINT NOT NULL DEFAULT 0
);
INSERT INTO v2_subscribe_monitor_control (id) VALUES (1) ON CONFLICT DO NOTHING;`

func (store *Store) EnsureMonitoring(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, ipIntelligenceSchema+monitorControlSchema+riskHistorySchema)
	store.monitorReady.Store(err == nil)
	return err
}

func monitorSchemaError(err error) bool {
	var failure *pgconn.PgError
	return errors.As(err, &failure) && (failure.Code == "42P01" || failure.Code == "42501" || failure.Code == "42703")
}

func withoutIPCache(query string) string {
	return strings.ReplaceAll(query, "v2_subscribe_ip_intelligence", "(SELECT NULL::varchar AS client_ip, '{}'::jsonb AS profile WHERE false)")
}

func (store *Store) enrichEvents(ctx context.Context, events []Event) {
	ips := make([]string, 0, len(events))
	profiles := map[string]IPIntelligence{}
	for _, event := range events {
		profile := readIPIntelligence(nil, event.IP, time.Now().Unix())
		if _, public := publicLookupIP(event.IP); !public {
			profile.GeoState, profile.RiskState = "non_public", "non_public"
		} else if !store.monitorReady.Load() {
			profile.GeoState, profile.RiskState = "unavailable", "unavailable"
		}
		profiles[event.IP] = profile
		ips = append(ips, event.IP)
	}
	if len(ips) > 0 && store.monitorReady.Load() {
		lookupCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		rows, err := store.db.QueryContext(lookupCtx, `SELECT client_ip,profile FROM v2_subscribe_ip_intelligence WHERE client_ip=ANY($1)`, ips)
		if err == nil {
			for rows.Next() {
				var ip string
				var raw []byte
				if err = rows.Scan(&ip, &raw); err != nil {
					break
				}
				profiles[ip] = readIPIntelligence(raw, ip, time.Now().Unix())
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
		}
		cancel()
		if err != nil {
			if monitorSchemaError(err) {
				store.monitorReady.Store(false)
			}
			for ip, profile := range profiles {
				profile.GeoState, profile.RiskState = "unavailable", "unavailable"
				profiles[ip] = profile
			}
		}
	}
	for index := range events {
		profile := profiles[events[index].IP]
		events[index].Intelligence = &profile
	}
}

func (store *Store) runMonitoring(ctx context.Context) {
	lookup := newIPLookup()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	var initializedAt, seededAt, assessedAt, loggedAt int64
	report := func(err error) {
		if err != nil && ctx.Err() == nil {
			if monitorSchemaError(err) {
				store.monitorReady.Store(false)
			}
			if now := time.Now().Unix(); now-loggedAt >= 60 {
				log.Print("subscription monitoring task failed; core subscription guard remains active")
				loggedAt = now
			}
		}
	}
	for {
		now := time.Now().Unix()
		if !store.monitorReady.Load() && now-initializedAt >= 60 {
			initializedAt = now
			initCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			report(store.EnsureMonitoring(initCtx))
			cancel()
		}
		if store.monitorReady.Load() {
			if now-seededAt >= 60 {
				seededAt = now
				seedCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				_, err := store.db.ExecContext(seedCtx, `INSERT INTO v2_subscribe_ip_intelligence (client_ip,last_seen)
SELECT client_ip,MAX(accessed_at) FROM v2_subscribe_guard_event
WHERE accessed_at > $1::bigint-86400 AND accessed_at <= $1 AND client_ip <> ''
GROUP BY client_ip ON CONFLICT (client_ip) DO UPDATE SET last_seen=GREATEST(v2_subscribe_ip_intelligence.last_seen,EXCLUDED.last_seen)`, now)
				report(err)
				if err == nil {
					_, err = store.db.ExecContext(seedCtx, `DELETE FROM v2_subscribe_ip_intelligence WHERE client_ip IN
(SELECT client_ip FROM v2_subscribe_ip_intelligence WHERE last_seen < $1::bigint-2592000 LIMIT 1000)`, now)
					report(err)
				}
				cancel()
			}
			if os.Getenv("SUBSCRIBE_IP_INTELLIGENCE_OFF") != "1" {
				lookupCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				report(store.enrichNextIP(lookupCtx, lookup, now))
				cancel()
			}
			if now-assessedAt >= 60 {
				assessedAt = now
				assessCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				report(store.captureRiskHistory(assessCtx, now))
				cancel()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type MonitorStatus struct {
	Ready       bool  `json:"ready"`
	ForceOff    bool  `json:"force_off"`
	Enabled     bool  `json:"enabled"`
	Revision    int64 `json:"revision"`
	Cached      int64 `json:"cached"`
	Pending     int64 `json:"pending"`
	Failed      int64 `json:"failed"`
	GeoReady    int64 `json:"geo_ready"`
	RiskReady   int64 `json:"risk_ready"`
	NextRequest int64 `json:"next_request"`
	LastChecked int64 `json:"last_checked"`
	SnapshotAt  int64 `json:"snapshot_at"`
}

func (store *Store) MonitoringStatus(ctx context.Context) (MonitorStatus, error) {
	status := MonitorStatus{Ready: store.monitorReady.Load(), ForceOff: os.Getenv("SUBSCRIBE_IP_INTELLIGENCE_OFF") == "1"}
	if !status.Ready {
		return status, nil
	}
	err := store.db.QueryRowContext(ctx, `SELECT ip_enabled,revision,snapshot_at FROM v2_subscribe_monitor_control WHERE id=1`).Scan(&status.Enabled, &status.Revision, &status.SnapshotAt)
	if err == nil {
		err = store.db.QueryRowContext(ctx, `SELECT COUNT(*),
COUNT(*) FILTER (WHERE profile='{}'::jsonb OR (profile->>'expires_at')::bigint <= $1),
COUNT(*) FILTER (WHERE profile->>'geo_state'='unavailable' OR profile->>'risk_state'='unavailable'),
COUNT(*) FILTER (WHERE profile->>'geo_state'='ok' AND (profile->>'expires_at')::bigint>$1),
COUNT(*) FILTER (WHERE profile->>'risk_state'='ok' AND (profile->>'expires_at')::bigint>$1),
COALESCE(MAX((profile->>'checked_at')::bigint),0) FROM v2_subscribe_ip_intelligence`, time.Now().Unix()).Scan(&status.Cached, &status.Pending, &status.Failed, &status.GeoReady, &status.RiskReady, &status.LastChecked)
	}
	if err == nil {
		err = store.db.QueryRowContext(ctx, `SELECT next_request FROM v2_subscribe_ip_lookup_rate WHERE id=1`).Scan(&status.NextRequest)
	}
	if monitorSchemaError(err) {
		store.monitorReady.Store(false)
		return MonitorStatus{ForceOff: status.ForceOff}, nil
	}
	return status, err
}

func (store *Store) SetIPLookup(ctx context.Context, enabled bool, revision, adminID int64) error {
	if !store.monitorReady.Load() {
		return ErrMonitorUnavailable
	}
	result, err := store.db.ExecContext(ctx, `UPDATE v2_subscribe_monitor_control SET ip_enabled=$1,revision=revision+1,updated_by=$2,updated_at=$3 WHERE id=1 AND revision=$4`, enabled, adminID, time.Now().Unix(), revision)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err == nil && count == 0 {
		return ErrConflict
	}
	return err
}

func (store *Store) RetryIPLookups(ctx context.Context) (int64, error) {
	if !store.monitorReady.Load() || os.Getenv("SUBSCRIBE_IP_INTELLIGENCE_OFF") == "1" {
		return 0, ErrMonitorUnavailable
	}
	result, err := store.db.ExecContext(ctx, `UPDATE v2_subscribe_ip_intelligence SET next_attempt=LEAST(next_attempt,$1)
WHERE client_ip IN (SELECT client_ip FROM v2_subscribe_ip_intelligence
WHERE (profile->>'geo_state'='unavailable' OR profile->>'risk_state'='unavailable') AND last_seen>$1::bigint-86400
AND lease_until<=$1 AND next_attempt>$1 ORDER BY next_attempt LIMIT 500 FOR UPDATE SKIP LOCKED)
AND lease_until<=$1 AND next_attempt>$1
AND EXISTS (SELECT 1 FROM v2_subscribe_monitor_control WHERE id=1 AND ip_enabled)`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

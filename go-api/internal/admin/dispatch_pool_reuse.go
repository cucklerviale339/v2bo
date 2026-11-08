package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Callers hold the dispatch advisory lock and address-table locks. Configuration
// references reserve an IP even when an investigation currently masks it: the
// original rule can still become a fallback. A monitor alone is not a lease.
func cloneDispatchPoolMonitor(ctx context.Context, tx *sql.Tx, source int64, host string) (int64, error) {
	refs, err := dispatchPoolReferences(ctx, tx)
	if err != nil {
		return 0, err
	}
	if len(refs[host]) != 0 {
		return 0, splitEditInvalid("新地址仍被下发配置或回退规则引用")
	}
	// Reporters lock probes before monitors. Take the same order before retiring
	// any old monitor, including probes no longer bound to the source entrance.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM v2_dns_probe WHERE enabled=1 ORDER BY id FOR SHARE`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var sourceHost string
	var port, interval, timeout int64
	err = tx.QueryRowContext(ctx, `SELECT host,check_port,check_interval_sec,tcp_timeout_ms FROM v2_dispatch_monitor WHERE id=$1 AND enabled AND NOT deleted FOR SHARE`, source).Scan(&sourceHost, &port, &interval, &timeout)
	if err != nil {
		return 0, err
	}
	if host == sourceHost {
		return 0, splitEditInvalid("不能将原入口重新分配为备用入口")
	}
	var oldID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM v2_dispatch_monitor WHERE host=$1 FOR UPDATE`, host).Scan(&oldID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	if err == nil {
		var managed bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_group WHERE active AND monitor_id=$1)`, oldID).Scan(&managed); err != nil {
			return 0, err
		}
		if managed {
			return 0, splitEditInvalid("旧监控仍被活跃分组使用")
		}
		// Keep its ID, tombstone and audit relationships; free only the unique
		// host key. A new ID prevents old samples, runs, lineage and incidents
		// from being credited to this allocation, even after later restarts.
		archiveHost := fmt.Sprintf("retired-monitor-%d-%d.invalid", oldID, time.Now().UnixNano())
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_monitor SET host=$2,enabled=FALSE,deleted=TRUE,version=version+1 WHERE id=$1`, oldID, archiveHost); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_monitor_probe WHERE monitor_id=$1`, oldID); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE v2_dispatch_auto_split_operation SET status='cancelled',reason='旧入口已退出使用，备用 IP 开始新一轮分配',updated_at=$2 WHERE monitor_id=$1 AND status='waiting'`, oldID, time.Now().Unix()); err != nil {
			return 0, err
		}
	}
	var id int64
	if err = tx.QueryRowContext(ctx, `INSERT INTO v2_dispatch_monitor(host,check_port,enabled,check_interval_sec,tcp_timeout_ms) VALUES($1,$2,TRUE,$3,$4) RETURNING id`, host, port, interval, timeout).Scan(&id); err != nil {
		return 0, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_monitor_probe(monitor_id,probe_id) SELECT $2,b.probe_id FROM v2_dispatch_monitor_probe b JOIN v2_dns_probe p ON p.id=b.probe_id AND p.enabled=1 WHERE b.monitor_id=$1`, source, id)
	if err != nil {
		return 0, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return 0, err
	} else if n == 0 {
		return 0, splitEditInvalid("原入口没有启用的绑定探针")
	}
	return id, nil
}

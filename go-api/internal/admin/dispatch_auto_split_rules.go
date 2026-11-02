package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"forest/go-api/internal/platform/userselector"
	usersvc "forest/go-api/internal/user"
)

func dispatchSplitRange(entry usersvc.DispatchEntry) (int64, int64, bool) {
	if len(entry.UserIDs) != 0 || len(entry.UserIDRanges) != 1 {
		return 0, 0, false
	}
	a, b, ok := userselector.ParseRange(entry.UserIDRanges[0])
	return a, b, ok && a < b
}

func dispatchSplitSpan(a, b int64) string { return fmt.Sprintf("%d-%d", a, b) }
func dispatchSplitScope(host string, a, b int64) usersvc.DispatchEntry {
	e := usersvc.DispatchEntry{Host: host, UserIDs: []string{}, UserIDRanges: []string{}}
	if a == b {
		e.UserIDs = []string{strconv.FormatInt(a, 10)}
	} else {
		e.UserIDRanges = []string{dispatchSplitSpan(a, b)}
	}
	return e
}

// All writes stay in the existing three address layers. Re-project the complete
// catalog before committing so overlapping rules cannot steal either half.
func applyDispatchSplitRules(ctx context.Context, tx *sql.Tx, before []usersvc.DispatchEntry, entry usersvc.DispatchEntry, ipA, ipB string, now int64) error {
	a, b, ok := dispatchSplitRange(entry)
	if !ok {
		return fmt.Errorf("入口须仅有一个至少含两个 ID 的范围，不能混有具体 ID")
	}
	mid := a + (b-a)/2
	rangeA, _ := json.Marshal([]string{dispatchSplitSpan(a, mid)})
	rangeB, _ := json.Marshal([]string{dispatchSplitSpan(mid+1, b)})
	if len(entry.Sources) == 0 {
		return fmt.Errorf("入口缺少可核实的地址来源")
	}
	for _, source := range entry.Sources {
		switch {
		case strings.HasPrefix(source, "内鬼管理规则 #"), strings.HasPrefix(source, "节点地址规则 #"):
			insider := strings.HasPrefix(source, "内鬼管理规则 #")
			prefix, table := "节点地址规则 #", "v2_node_address_rule"
			if insider {
				prefix, table = "内鬼管理规则 #", "v2_insider_rule"
			}
			id, err := strconv.ParseInt(strings.TrimPrefix(source, prefix), 10, 64)
			if err != nil || id <= 0 {
				return fmt.Errorf("地址来源无效")
			}
			var host, ids, ranges, extras string
			var group int64
			query := `SELECT host,match_user_ids,match_user_id_ranges,extra_nodes FROM ` + table + ` WHERE id=$1 AND enabled=1`
			if err = tx.QueryRowContext(ctx, query, id).Scan(&host, &ids, &ranges, &extras); err != nil {
				return err
			}
			var rawIDs, rawRanges, rawExtras []string
			if json.Unmarshal([]byte(ids), &rawIDs) != nil || json.Unmarshal([]byte(ranges), &rawRanges) != nil || json.Unmarshal([]byte(extras), &rawExtras) != nil || len(rawIDs) != 0 || len(rawRanges) != 1 || len(rawExtras) != 0 || normalizeDispatchMonitorHost(host) != entry.Host || strings.ContainsAny(host, ",()") {
				return fmt.Errorf("来源规则不是单一范围及单一地址，或含额外节点，跳过自动修改")
			}
			lo, hi, valid := userselector.ParseRange(rawRanges[0])
			if !valid || lo != a || hi != b {
				return fmt.Errorf("来源规则范围与有效下发范围不同，跳过自动修改")
			}
			if _, err = tx.ExecContext(ctx, `UPDATE `+table+` SET host=$2,match_user_id_ranges=$3,name=left(name,230)||' / A',updated_at=$4 WHERE id=$1`, id, ipA, string(rangeA), now); err != nil {
				return err
			}
			if insider {
				_, err = tx.ExecContext(ctx, `INSERT INTO v2_insider_rule(name,host,match_user_id_ranges,enabled,created_at,updated_at) VALUES($1,$2,$3,1,$4,$4)`, fmt.Sprintf("自动二分 #%d / B", id), ipB, string(rangeB), now)
			} else {
				if err = tx.QueryRowContext(ctx, `SELECT group_id FROM v2_node_address_rule WHERE id=$1`, id).Scan(&group); err != nil {
					return err
				}
				// Reserve the next priority slot immediately after A, including ties.
				if _, err = tx.ExecContext(ctx, `WITH ordered AS (SELECT id,row_number() OVER(ORDER BY sort NULLS LAST,id)*2 AS n FROM v2_node_address_rule WHERE group_id=$1) UPDATE v2_node_address_rule r SET sort=o.n FROM ordered o WHERE r.id=o.id`, group); err != nil {
					return err
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO v2_node_address_rule(group_id,name,host,match_user_id_ranges,enabled,sort,created_at,updated_at) SELECT group_id,$2,$3,$4,1,sort+1,$5,$5 FROM v2_node_address_rule WHERE id=$1`, id, fmt.Sprintf("自动二分 #%d / B", id), ipB, string(rangeB), now)
			}
			if err != nil {
				return err
			}
		case strings.HasPrefix(source, "节点管理 "):
			parts := strings.Split(strings.TrimPrefix(source, "节点管理 "), " #")
			if len(parts) != 2 {
				return fmt.Errorf("节点来源无效")
			}
			valid := false
			for _, kind := range []string{"shadowsocks", "vmess", "trojan", "tuic", "hysteria", "vless", "anytls", "v2node"} {
				if parts[0] == kind {
					valid = true
				}
			}
			id, err := strconv.ParseInt(parts[1], 10, 64)
			if !valid || err != nil || id <= 0 {
				return fmt.Errorf("节点来源无效")
			}
			var host string
			if err = tx.QueryRowContext(ctx, `SELECT host FROM v2_server_`+parts[0]+` WHERE id=$1 AND "show"=1`, id).Scan(&host); err != nil {
				return err
			}
			if normalizeDispatchMonitorHost(host) != entry.Host || strings.ContainsAny(host, ",()") {
				return fmt.Errorf("节点管理中的条件地址不自动修改")
			}
			var group int64
			var enabled int64
			err = tx.QueryRowContext(ctx, `SELECT g.id,g.enabled FROM v2_node_address_binding b JOIN v2_node_address_group g ON g.id=b.address_group_id WHERE b.server_type=$1 AND b.server_id=$2`, parts[0], id).Scan(&group, &enabled)
			if err == sql.ErrNoRows {
				err = tx.QueryRowContext(ctx, `INSERT INTO v2_node_address_group(name,description,enabled,created_at,updated_at) VALUES($1,'入口监控自动二分',1,$2,$2) RETURNING id`, fmt.Sprintf("自动二分 %s #%d", parts[0], id), now).Scan(&group)
				if err == nil {
					_, err = tx.ExecContext(ctx, `INSERT INTO v2_node_address_binding(address_group_id,server_type,server_id,created_at,updated_at) VALUES($1,$2,$3,$4,$4)`, group, parts[0], id, now)
				}
			} else if err == nil && enabled != 1 {
				return fmt.Errorf("节点绑定的地址组已停用，跳过自动修改")
			}
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `WITH ordered AS (SELECT id,row_number() OVER(ORDER BY sort NULLS LAST,id)*2 AS n FROM v2_node_address_rule WHERE group_id=$1) UPDATE v2_node_address_rule r SET sort=o.n FROM ordered o WHERE r.id=o.id`, group); err != nil {
				return err
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO v2_node_address_rule(group_id,name,host,match_user_id_ranges,sort,created_at,updated_at) SELECT $1,'自动二分 / A',$2,$3,COALESCE(max(sort),0)+1,$4,$4 FROM v2_node_address_rule WHERE group_id=$1`, group, ipA, string(rangeA), now)
			if err == nil {
				_, err = tx.ExecContext(ctx, `INSERT INTO v2_node_address_rule(group_id,name,host,match_user_id_ranges,sort,created_at,updated_at) SELECT $1,'自动二分 / B',$2,$3,COALESCE(max(sort),0)+1,$4,$4 FROM v2_node_address_rule WHERE group_id=$1`, group, ipB, string(rangeB), now)
			}
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("不支持的地址来源")
		}
	}
	after, err := usersvc.DispatchEntriesFrom(ctx, tx)
	if err != nil {
		return err
	}
	scopes := func(entries []usersvc.DispatchEntry) map[string][2]string {
		out := map[string][2]string{}
		for _, e := range entries {
			ids, _ := json.Marshal(e.UserIDs)
			ranges, _ := json.Marshal(e.UserIDRanges)
			out[e.Host] = [2]string{string(ids), string(ranges)}
		}
		return out
	}
	expected := []usersvc.DispatchEntry{}
	for _, e := range before {
		if e.Host != entry.Host {
			expected = append(expected, e)
		}
	}
	expected = append(expected, dispatchSplitScope(ipA, a, mid), dispatchSplitScope(ipB, mid+1, b))
	if !reflect.DeepEqual(scopes(expected), scopes(after)) {
		return fmt.Errorf("二分后下发范围受其他规则影响，已取消全部改动")
	}
	return nil
}

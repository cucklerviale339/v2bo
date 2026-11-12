package user

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Full-site dispatch preserves each node's port. A TCP pool check on just the
// source monitor port cannot establish that all those ports are reachable.
func ManagedDispatchPortsFrom(ctx context.Context, q DispatchQueryer) ([]int64, error) {
	ports := map[int64]bool{}
	for _, table := range serverFetchTables {
		rows, err := q.QueryContext(ctx, `SELECT port FROM `+table.table+` WHERE "show"=1 ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				break
			}
			if table.serverType == "tuic" || table.serverType == "hysteria" {
				err = fmt.Errorf("全站含UDP节点，当前TCP探针不能验证其承载能力")
				break
			}
			for _, part := range strings.Split(raw, ",") {
				bounds := strings.Split(strings.TrimSpace(part), "-")
				a, e := strconv.ParseInt(bounds[0], 10, 64)
				b := a
				if len(bounds) == 2 {
					b, e = strconv.ParseInt(bounds[1], 10, 64)
				}
				if e != nil || len(bounds) > 2 || a < 1 || b < a || b > 65535 || b-a > 63 {
					err = fmt.Errorf("全站含无法自动验证的节点端口 %q", raw)
					break
				}
				for p := a; p <= b; p++ {
					ports[p] = true
				}
			}
			if err != nil {
				break
			}
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	out := []int64{}
	for p := range ports {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

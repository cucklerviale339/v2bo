package admin

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPostgresInvestigationCurrentEntryFaultDecision(t *testing.T) {
	for _, tc := range []struct {
		name       string
		kind       string
		reason     string
		partitions []int
	}{
		{"old_exposure_filter", "filtered", "", []int{2, 6}},
		{"old_exposure_bisect", "bisected", "", []int{4, 4}},
		{"old_exposure_single_pull", "filtered", "", []int{1, 7}},
		{"current_shared_dispatch", "recovered", "当前入口实际仍下发给组外用户", []int{8}},
		{"incomplete_receipts", "recovered", "本轮拉取证据不完整", []int{8}},
		{"failover_policy", "recovered", "分组设置为仅故障转移", []int{8}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.enableLifecycle()
			g := f.group("range.example")
			f.pool("192.0.2.201", "192.0.2.202")
			pulled := []int64{11, 12}
			switch tc.name {
			case "old_exposure_bisect":
				pulled = investigationGroupIDs(g)
			case "old_exposure_single_pull":
				pulled = []int64{11}
			case "failover_policy":
				f.exec(`UPDATE v2_dispatch_investigation_group SET policy='failover' WHERE id=$1`, g.ID)
			}
			f.outage(g, pulled)
			// User 5 had the same IP in an earlier round, but normally still
			// receives the independent control address.
			f.exec(`INSERT INTO v2_dispatch_host_exposure(host,user_id,first_at,last_at)
SELECT host,5,epoch_at-86400,epoch_at-3600 FROM v2_dispatch_investigation_group WHERE id=$1`, g.ID)
			switch tc.name {
			case "current_shared_dispatch":
				// Add a live assignment after the original roster was frozen.
				f.exec(`INSERT INTO v2_node_address_rule(group_id,name,host,match_user_ids,created_at,updated_at)
VALUES(1,'current assignment outside this group','range.example','["5"]',1,1)`)
				f.assertUserHosts(5, g.Host)
			case "incomplete_receipts":
				f.exec(`UPDATE v2_dispatch_investigation_health SET delivery_failure_at=$1 WHERE id=1`, time.Now().Unix())
			}
			f.execProcess(g.ID)

			var kind string
			var raw []byte
			err := f.db.QueryRow(`SELECT kind,payload FROM v2_dispatch_investigation_event
WHERE group_id=$1 AND kind IN('filtered','bisected','recovered') ORDER BY id DESC LIMIT 1`, g.ID).Scan(&kind, &raw)
			if err != nil || kind != tc.kind {
				t.Fatalf("expected %s, got %s: %v, groups: %v", tc.kind, kind, err, f.groups())
			}
			var history struct {
				Reason       string                   `json:"reason"`
				Pulled       []int64                  `json:"pulled_ids"`
				Partitions   []investigationPartition `json:"partitions"`
				Confirmation json.RawMessage          `json:"confirmation"`
			}
			if err := json.Unmarshal(raw, &history); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(history.Pulled, pulled) || (tc.reason != "" && !strings.Contains(history.Reason, tc.reason)) {
				t.Fatalf("incorrect pull record or reason: %s", raw)
			}
			sizes := []int{}
			hosts := map[string]bool{}
			for _, part := range history.Partitions {
				sizes = append(sizes, len(part.IDs))
				if part.Host == g.Host || hosts[part.Host] || part.Kind == "confirmed" {
					t.Fatalf("invalid partition: %+v", part)
				}
				hosts[part.Host] = true
				f.assertCheckPort(part.Host, 18443)
				for _, id := range part.IDs {
					f.assertUserHosts(id, part.Host)
				}
			}
			if !reflect.DeepEqual(sizes, tc.partitions) || string(history.Confirmation) != "null" {
				t.Fatalf("unexpected partitions or confirmation: %s", raw)
			}
			outsideHost := "base.example"
			if tc.name == "current_shared_dispatch" {
				outsideHost = g.Host
			}
			f.assertUserHosts(5, outsideHost)
		})
	}
}

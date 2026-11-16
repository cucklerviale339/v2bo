package admin

import (
	"encoding/json"
	"forest/go-api/internal/platform/postgres"
	"os"
	"reflect"
	"strconv"
	"testing"
)

// Replay only dispatch audit/membership facts into an isolated test schema.
// Never connects to a production DSN or calls an automatic action.
func TestPostgresInvestigationBranchRiskProductionSnapshotSQLParity(t *testing.T) {
	base := os.Getenv("DISPATCH_RISK_SNAPSHOT_DIR")
	if base == "" {
		t.Skip("no read-only audit snapshots supplied")
	}
	for _, site := range []string{"35", "39"} {
		t.Run(site, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			raw, err := os.ReadFile(base + "/stage-repair-" + site + "-snapshot.json")
			if err != nil {
				t.Fatal(err)
			}
			var snap struct {
				Events []postgres.DispatchRiskEvent `json:"events"`
				Groups []struct {
					ID   int64  `json:"id"`
					Role string `json:"lifecycle_role"`
				} `json:"groups"`
			}
			if err = json.Unmarshal(raw, &snap); err != nil {
				t.Fatal(err)
			}
			raw, err = os.ReadFile(base + "/stage-repair-" + site + "-effective.json")
			if err != nil {
				t.Fatal(err)
			}
			var effective struct {
				Members map[string]struct{ IDs map[string]bool } `json:"effective_members"`
			}
			if err = json.Unmarshal(raw, &effective); err != nil {
				t.Fatal(err)
			}
			f.exec(`DELETE FROM v2_dispatch_risk_member;DELETE FROM v2_dispatch_risk_case;DELETE FROM v2_dispatch_investigation_event;DELETE FROM v2_dispatch_investigation_member`)
			for _, e := range snap.Events {
				f.exec(`INSERT INTO v2_dispatch_investigation_event(id,root_id,group_id,kind,created_at,payload) VALUES($1,$2,$3,$4,$5,$6)`, e.ID, e.RootID, e.GroupID, e.Kind, e.CreatedAt, string(e.Payload))
			}
			// Refresh is the exact transaction used by startup migration and new audits.
			tx, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err = postgres.RefreshDispatchRisk(f.ctx, tx); err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			cases, members, err := postgres.ProjectDispatchRisk(snap.Events)
			if err != nil {
				t.Fatal(err)
			}
			states := postgres.DispatchRiskUsers(cases, members)
			byTime := map[int64]int64{}
			for _, e := range snap.Events {
				byTime[e.ID] = e.CreatedAt
			}
			for _, group := range snap.Groups {
				if group.Role != "stable" && group.Role != "whitelist" {
					continue
				}
				fixture := f.group("range.example")
				f.exec(`UPDATE v2_dispatch_investigation_group SET lifecycle_role=$2 WHERE id=$1`, fixture.ID, group.Role)
				wanted := []string{}
				expected := []int64{}
				auto, manual := map[int64]int64{}, map[int64]int64{}
				required := int64(3 * 86400)
				if group.Role == "whitelist" {
					required = 7 * 86400
				}
				for _, e := range snap.Events {
					var p struct {
						Target int64   `json:"target_group_id"`
						Users  []int64 `json:"user_ids"`
						Added  []int64 `json:"added_ids"`
					}
					if err = json.Unmarshal(e.Payload, &p); err != nil {
						t.Fatal(err)
					}
					if (e.Kind == "stable_promoted" || e.Kind == "whitelist_promoted") && p.Target == group.ID {
						for _, id := range p.Users {
							auto[id] = e.ID
						}
						f.exec(`UPDATE v2_dispatch_investigation_event SET payload=jsonb_set(payload,'{target_group_id}',to_jsonb($2::bigint)) WHERE id=$1`, e.ID, fixture.ID)
					}
					if e.Kind == "edited" && e.GroupID == group.ID {
						for _, id := range p.Added {
							manual[id] = e.ID
						}
						f.exec(`UPDATE v2_dispatch_investigation_event SET group_id=$2 WHERE id=$1`, e.ID, fixture.ID)
					}
				}
				for raw := range effective.Members[strconv.FormatInt(group.ID, 10)].IDs {
					id, err := strconv.ParseInt(raw, 10, 64)
					if err != nil {
						t.Fatal(err)
					}
					wanted = append(wanted, raw)
					st := states[id]
					if auto[id] > manual[id] && (st.Blocked || (st.ReleasedAt > 0 && byTime[auto[id]] < st.ReleasedAt+required)) {
						expected = append(expected, id)
					}
				}
				roster, _ := json.Marshal(wanted)
				f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at) SELECT id,'audit-'||id||'@example.test','h','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM (SELECT value::bigint id FROM jsonb_array_elements_text($1::jsonb)) x ON CONFLICT(id) DO NOTHING`, string(roster))
				f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id) SELECT $1,'range.example',value::bigint,$1 FROM jsonb_array_elements_text($2::jsonb)`, fixture.ID, string(roster))
				fixture.LifecycleRole = group.Role
				fixture.UserIDs = wanted
				tx, err := f.db.BeginTx(f.ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				got, err := investigationStageCorrectionIDs(f.ctx, tx, fixture)
				tx.Rollback()
				if err != nil {
					t.Fatal(err)
				}
				gotSet, wantSet := map[int64]bool{}, map[int64]bool{}
				for _, id := range got {
					gotSet[id] = true
				}
				for _, id := range expected {
					wantSet[id] = true
				}
				if !reflect.DeepEqual(gotSet, wantSet) {
					t.Fatal("SQL correction and read-only backend audit disagree", len(gotSet), len(wantSet))
				}
				t.Logf("site=%s actual_stage=%d effective=%d corrected=%d remaining=%d SQL parity passed", site, group.ID, len(wanted), len(gotSet), len(wanted)-len(gotSet))
			}
		})
	}
}

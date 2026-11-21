package admin

import (
	"strings"
	"testing"

	"forest/go-api/internal/platform/postgres"
)

func TestPostgresInvestigationHistoryCompatibilityAndRecovery(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		name := "legacy audit snapshots"
		if corrupt {
			name = "damaged screening evidence"
		}
		t.Run(name, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload)
VALUES ($1,$1,'edited',1,'{"before":[{"id":1,"host":"range.example"}],"after":{"host":"range.example"},"added_ids":[]}'),
       ($1,$1,'edited',2,'{"before":{"host":"range.example"},"after":{"host":"range.example"}}'),
       ($1,$1,'future_display_event',3,'["any","display","shape"]')`, g.ID)
			var brokenID int64
			if corrupt {
				if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload)
VALUES ($1,$1,'filtered',4,'{"pulled_ids":{"11":true},"partitions":{"invalid":true}}') RETURNING id`, g.ID).Scan(&brokenID); err != nil {
					t.Fatal(err)
				}
			}
			// Cold-start initialization replays audit history before the worker can
			// advance. Production fails here before it handles any group.
			if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
				t.Fatal(err)
			}
			issue, err := postgres.ReadDispatchRiskHistoryIssue(f.ctx, f.db)
			if err != nil || (issue != nil) != corrupt {
				t.Fatalf("unexpected history status: %+v, %v", issue, err)
			}
			if issue != nil && (issue.EventID != brokenID || issue.GroupID != g.ID) {
				t.Fatalf("wrong event in history status: %+v", issue)
			}

			f.pool("192.0.2.201", "192.0.2.202")
			f.outage(g, []int64{11, 12})
			if err := f.s.runInvestigationCycle(f.ctx); err != nil {
				t.Fatal(err)
			}
			var processed int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event
WHERE group_id=$1 AND kind='filtered' AND id<>$2 AND risk_payload->>'risk_schema_version'='1'
AND risk_payload->'pulled_ids' @> '[11,12]'::jsonb`, g.ID, brokenID).Scan(&processed); err != nil || processed != 1 {
				t.Fatalf("fault cycle did not continue (%d): %v, groups: %v", processed, err, f.groups())
			}
			var legacyRows int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='edited' AND jsonb_typeof(payload->'before')='array'`).Scan(&legacyRows); err != nil || legacyRows != 1 {
				t.Fatalf("original audit changed (%d): %v", legacyRows, err)
			}
			if !corrupt {
				return
			}

			tx, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = investigationAudit(f.ctx, tx, g.ID, g.ID, "filtered", 0, map[string]any{"pulled_ids": "invalid"})
			tx.Rollback()
			if err == nil {
				t.Fatal("writer accepted an undecodable screening event")
			}
			tx, err = f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			var reason string
			err = f.s.promoteInvestigation(f.ctx, tx, g, nil, func(s string) error { reason = s; return nil })
			tx.Rollback()
			if err != nil || !strings.Contains(reason, "暂缓自动晋级") {
				t.Fatalf("promotion used incomplete risk history: %q %v", reason, err)
			}

			f.exec(`UPDATE v2_dispatch_investigation_event SET payload='{"pulled_ids":[],"unpulled_ids":[]}' WHERE id=$1`, brokenID)
			f.exec(`UPDATE v2_dispatch_investigation_event SET payload=jsonb_set(payload,'{pulled_ids}','{}')
WHERE group_id=$1 AND risk_payload->>'risk_schema_version'='1' AND kind='filtered'`, g.ID)
			if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
				t.Fatal(err)
			}
			issue, err = postgres.ReadDispatchRiskHistoryIssue(f.ctx, f.db)
			if err != nil || issue != nil {
				t.Fatalf("history replay did not recover after repair: %+v %v", issue, err)
			}
			var restored int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_risk_member WHERE user_id IN(11,12)`).Scan(&restored); err != nil || restored < 2 {
				t.Fatalf("processing during the history issue was lost (%d): %v", restored, err)
			}
		})
	}
}

func TestPostgresInvestigationHistoryDiscoveryFailureKeepsExistingGroupsRunning(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.pool("192.0.2.201", "192.0.2.202")
	f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at)
VALUES (8,'[1]','new entry','discovery.example','443',443,'1','tcp',1,1,1)`)
	f.s.invalidateDispatchCatalog()
	f.save("discovery.example", f.pid)
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.outage(g, []int64{11, 12})
	newGroup := f.group("discovery.example")
	// Keep both healthy probe controls in place and force discovery to retry
	// the new entry during this cycle.
	f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1`, newGroup.ID)
	f.exec(`DELETE FROM v2_dispatch_investigation_group WHERE id=$1`, newGroup.ID)
	f.exec(`
CREATE FUNCTION reject_new_investigation_root() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.host='discovery.example' THEN
  RAISE EXCEPTION 'simulated discovery failure';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reject_new_investigation_root BEFORE INSERT ON v2_dispatch_investigation_group
FOR EACH ROW EXECUTE FUNCTION reject_new_investigation_root()`)
	err := f.s.runInvestigationCycle(f.ctx)
	if err == nil || !strings.Contains(err.Error(), "初始化入口分组") {
		t.Fatalf("expected explicit discovery failure, got %v", err)
	}
	if f.successfulEvents() != 1 {
		t.Fatal("discovery failure skipped the existing group's fault", f.groups())
	}
}

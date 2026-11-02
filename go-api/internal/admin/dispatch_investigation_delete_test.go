package admin

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestPostgresInvestigationDeleteExcludesWithoutDeletingData(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint("enabled=", enabled), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "manual", Host: "192.0.2.250", ManualOnly: true}); err != nil {
				t.Fatal(err)
			}
			g = f.group("192.0.2.250")
			f.exec(`INSERT INTO v2_dispatch_investigation_delivery VALUES($1,$2,11,$3)`, g.ID, g.Generation, time.Now().Unix())
			f.exec(`INSERT INTO v2_dispatch_investigation_delivery_recent VALUES($1,$2,11,$3)`, g.ID, g.Generation, time.Now().Unix())
			f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=$1`, enabled)
			original := f.snapshot("v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding", "v2_server_vmess", "v2_user")
			evidence := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent", "v2_dispatch_investigation_event")
			other := f.group("base.example")
			if err := f.s.DeleteDispatchMonitors(f.ctx, []string{g.Host}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(original, f.snapshot("v2_node_address_rule", "v2_node_address_group", "v2_node_address_binding", "v2_server_vmess", "v2_user")) {
				t.Fatal("original configuration changed")
			}
			if !reflect.DeepEqual(evidence, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent", "v2_dispatch_investigation_event")) {
				t.Fatal("deletion erased membership or evidence")
			}
			var active bool
			if err := f.db.QueryRow(`SELECT active FROM v2_dispatch_investigation_group WHERE id=$1`, g.ID).Scan(&active); err != nil || active {
				t.Fatal("deleted entry still active", active, err)
			}
			view, err := f.s.GetInvestigation(f.ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, shown := range view.Groups {
				if shown.ID == g.ID {
					t.Fatal("deleted entry still shown")
				}
			}
			for _, event := range view.Events {
				if event.GroupID == g.ID {
					t.Fatal("deleted entry history still shown")
				}
			}
			if got := f.group(other.Host); !reflect.DeepEqual(got, other) {
				t.Fatal("unrelated group changed", got)
			}
			u := usersvc.NewDBService(f.s.cfg, f.db)
			servers, err := u.Servers(f.ctx, 11, "")
			if err != nil || fmt.Sprint(servers[0]["host"]) != "range.example" {
				t.Fatal("override survived deletion", servers, err)
			}
			if err = u.RecordInvestigationDelivery(f.ctx, 11, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, time.Now().Unix()); err != nil {
				t.Fatal(err)
			}
			var late int
			if err = f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_delivery_recent WHERE group_id=$1`, g.ID).Scan(&late); err != nil || late != 1 {
				t.Fatal("late receipt changed excluded evidence", late, err)
			}
			if err = f.s.processInvestigation(f.ctx, g.ID); err != nil {
				t.Fatal(err)
			}
			if err = f.s.investigationCycle(f.ctx); err != nil {
				t.Fatal(err)
			}
			for _, got := range f.groups() {
				if got.MonitorID == g.MonitorID {
					t.Fatal("deleted entry bootstrapped again")
				}
			}
		})
	}
}

func TestPostgresInvestigationDeleteExistingTombstoneWhileOff(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=FALSE`)
	f.exec(`UPDATE v2_dispatch_monitor SET deleted=TRUE,enabled=FALSE WHERE id=$1`, g.MonitorID)
	if err := f.s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	view, err := f.s.GetInvestigation(f.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range view.Groups {
		if got.ID == g.ID {
			t.Fatal("old deleted group retained")
		}
	}
	if view.Settings.Enabled {
		t.Fatal("cleanup changed master switch")
	}
	for _, e := range view.Events {
		if e.GroupID == g.ID {
			t.Fatal("deleted history retained")
		}
	}
	before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event")
	if err = f.s.InitializeDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event")) {
		t.Fatal("repeat cleanup not idempotent")
	}
}

func TestPostgresInvestigationDeleteRollbackIsAtomic(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.exec(`CREATE FUNCTION reject_investigation_exclusion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.active AND NOT NEW.active THEN RAISE EXCEPTION 'test_reject_investigation_delete'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_investigation_exclusion BEFORE UPDATE ON v2_dispatch_investigation_group FOR EACH ROW EXECUTE FUNCTION reject_investigation_exclusion()`)
	tables := []string{"v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event"}
	before := f.snapshot(tables...)
	if err := f.s.DeleteDispatchMonitors(f.ctx, []string{g.Host}); err == nil || !strings.Contains(err.Error(), "test_reject_investigation_delete") {
		t.Fatal("expected atomic failure", err)
	}
	if !reflect.DeepEqual(before, f.snapshot(tables...)) {
		t.Fatal("failed deletion partially committed")
	}
}

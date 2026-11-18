package admin

import (
	"context"
	"errors"
	"reflect"
	"testing"

	usersvc "forest/go-api/internal/user"
)

func TestDispatchMonitorOwnershipQueryFailureStopsTasks(t *testing.T) {
	s, mock := newDispatchTestService(t)
	want := errors.New("account lookup unavailable")
	mock.ExpectQuery(`SELECT DISTINCT scope.host FROM jsonb_to_recordset`).WillReturnError(want)
	if tasks, err := s.ListDispatchProbeTasks(context.Background(), 7); !errors.Is(err, want) || len(tasks) != 0 {
		t.Fatal("account lookup failed open", tasks, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresDispatchMonitorHidesUnoccupiedConfiguredIDs(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	oldTask := f.tasks(f.pid)[g.Host]
	f.report(f.pid, oldTask, 2, 1, 0)
	// Same shape as production: the enabled rule keeps absent numeric IDs,
	// while investigation redirects all its existing recipients to a new host.
	f.exec(`UPDATE v2_dispatch_investigation_group SET host='replacement.example' WHERE id=$1`, g.ID)
	f.s.invalidateDispatchCatalog()
	f.save("replacement.example", f.pid)
	tables := []string{"v2_node_address_rule", "v2_insider_rule", "v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_monitor_state", "v2_dispatch_history"}
	before := f.snapshot(tables...)
	if _, ok := f.monitors(false)[g.Host]; ok {
		t.Fatal("no actual recipients, but old entry still displayed")
	}
	if _, ok := f.monitors(true)[g.Host]; ok {
		t.Fatal("including deleted monitors revived unoccupied entry")
	}
	if _, ok := f.monitors(false)["replacement.example"]; !ok {
		t.Fatal("replacement with actual recipients hidden")
	}
	tasks := f.tasks(f.pid)
	if _, ok := tasks[g.Host]; ok {
		t.Fatal("unoccupied old address still scheduled")
	}
	if task, ok := tasks["replacement.example"]; !ok || task.CheckPort != 18443 {
		t.Fatal("replacement task or custom port missing", tasks)
	}
	if !reflect.DeepEqual(before, f.snapshot(tables...)) {
		t.Fatal("monitor filtering modified rules, assignments, config or history")
	}
	configured, err := f.s.dispatchEntries(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	retained := false
	for _, entry := range configured {
		retained = retained || entry.Host == g.Host
	}
	if !retained {
		t.Fatal("configured numeric ranges were removed")
	}
	f.s.dispatchCacheMu.Lock()
	var cached usersvc.DispatchEntry
	cached, retained = f.s.dispatchCachedScopes[g.Host]
	f.s.dispatchCacheMu.Unlock()
	if !retained || len(cached.UserIDRanges)+len(cached.UserIDs) == 0 || len(cached.Sources) == 0 {
		t.Fatal("monitor filter erased configured ownership from pool/history cache", cached)
	}
	// A new actual recipient reactivates the original saved monitoring config.
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at)
VALUES(20,'new-recipient@example.test','hash','00000000-0000-0000-0000-000000000020','00000000000000000000000000000020',1,1,0,1,1)`)
	f.s.invalidateDispatchCatalog()
	if m, ok := f.monitors(false)[g.Host]; !ok || m.CheckPort != 18443 || m.ID != -oldTask.TargetID {
		t.Fatal("new recipient did not restore existing monitor config", m)
	}
	if task, ok := f.tasks(f.pid)[g.Host]; !ok || task.TargetVersion != oldTask.TargetVersion || task.CheckPort != oldTask.CheckPort {
		t.Fatal("original task config lost on reactivation", task)
	}
	// Frozen investigation rosters outlive deleted accounts. They must not keep
	// the replacement entry monitored after its last actual account is gone.
	f.exec(`DELETE FROM v2_user WHERE id IN(SELECT user_id FROM v2_dispatch_investigation_member WHERE group_id=$1)`, g.ID)
	f.s.invalidateDispatchCatalog()
	if _, ok := f.monitors(false)["replacement.example"]; ok {
		t.Fatal("deleted recipients kept replacement visible")
	}
	if _, ok := f.tasks(f.pid)["replacement.example"]; ok {
		t.Fatal("deleted recipients kept replacement scheduled")
	}
	// The unmodified subscription projection still assigns the new user normally.
	entries, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Host == g.Host && usersvc.DispatchEntryContains(entry, 20) {
			return
		}
	}
	t.Fatal("new user's original dispatch rule changed")
}

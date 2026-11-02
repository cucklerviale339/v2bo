package admin

import (
	"errors"
	"reflect"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func splitEditValue(g DispatchAutoSplitGroup) DispatchSplitGroupEdit {
	return DispatchSplitGroupEdit{ID: g.ID, Revision: g.Revision, ParentGroupID: g.ParentGroupID, Host: g.Host, IDRange: g.IDRange}
}
func splitTestGroups(f *splitIntegration) map[int64]DispatchAutoSplitGroup {
	f.t.Helper()
	out := map[int64]DispatchAutoSplitGroup{}
	for _, g := range f.view().Groups {
		out[g.ID] = g
	}
	return out
}
func TestPostgresDispatchSplitEditActualRulesAndRollback(t *testing.T) {
	f := newSplitIntegration(t)
	f.pool("192.0.2.101", "192.0.2.102")
	c := f.timeout("range.example")
	f.enable()
	if !f.process(c) {
		t.Fatal(f.view())
	}
	historical := f.view().Operations[0]
	groups := splitTestGroups(f)
	a, b := splitEditValue(groups[historical.ChildAID]), splitEditValue(groups[historical.ChildBID])
	oldVersion := int64(0)
	if err := f.db.QueryRow(`SELECT version FROM v2_dispatch_monitor WHERE id=$1`, groups[a.ID].MonitorID).Scan(&oldVersion); err != nil {
		t.Fatal(err)
	}
	a.Host = "edited-a.example"
	a.IDRange = "10-49"
	b.Host = "edited-b.example"
	b.IDRange = "50-100"
	request := DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a, b}}
	if err := f.s.EditDispatchSplitGroups(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	view := f.view()
	if !reflect.DeepEqual(view.Operations[0], historical) {
		t.Fatal("historical success or quota timestamp rewritten", view.Operations[0], historical)
	}
	actual, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string][]splitEditSpan{}
	for _, e := range actual {
		scopes[e.Host] = splitEntrySpans(e)
	}
	if !reflect.DeepEqual(scopes[a.Host], []splitEditSpan{{10, 49}}) || !reflect.DeepEqual(scopes[b.Host], []splitEditSpan{{50, 100}}) {
		t.Fatal(scopes)
	}
	var version, stale int64
	if err = f.db.QueryRow(`SELECT version,(SELECT count(*) FROM v2_dispatch_monitor_state WHERE monitor_id=$1) FROM v2_dispatch_monitor WHERE id=$1`, groups[a.ID].MonitorID).Scan(&version, &stale); err != nil || version != oldVersion+1 || stale != 0 {
		t.Fatal("old state survived edit", version, stale, err)
	}
	var port string
	_ = f.db.QueryRow(`SELECT port FROM v2_server_vmess WHERE id=7`).Scan(&port)
	if port != "443" {
		t.Fatal("subscription port changed")
	}
	if err = f.s.EditDispatchSplitGroups(f.ctx, request); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("stale form accepted", err)
	}
	groups = splitTestGroups(f)
	a = splitEditValue(groups[a.ID])
	b = splitEditValue(groups[b.ID])
	a.IDRange = "10-70"
	b.IDRange = "60-100"
	if err = f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a, b}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("overlapping ranges accepted", err)
	}
	after, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil || !reflect.DeepEqual(actual, after) {
		t.Fatal("failed batch was not atomic", err)
	}
	a = splitEditValue(groups[a.ID])
	a.Host = "base.example"
	if err = f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("existing address accepted", err)
	}
	// A monitor tombstone collision is checked after rule writes: the whole
	// transaction, including revisions and lineage, must still roll back.
	f.exec(`INSERT INTO v2_dispatch_monitor(host,check_port,enabled,deleted,check_interval_sec,tcp_timeout_ms) VALUES('reserved.example',18443,FALSE,TRUE,30,500)`)
	a = splitEditValue(groups[a.ID])
	a.Host = "reserved.example"
	if err = f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("tombstone collision accepted", err)
	}
	rolledBack, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil || !reflect.DeepEqual(rolledBack, actual) {
		t.Fatal("late monitor conflict partially wrote rules", err)
	}
	if !reflect.DeepEqual(groups, splitTestGroups(f)) {
		t.Fatal("late conflict changed group revisions")
	}
	root := splitEditValue(groups[historical.GroupID])
	root.Host = "rewritten-history.example"
	if err = f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{root}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("inactive ancestor address edited", err)
	}
}

func TestPostgresDispatchSplitEditInsiderRules(t *testing.T) {
	f := newSplitIntegration(t)
	f.exec(`INSERT INTO v2_insider_rule(name,host,match_user_id_ranges,enabled,created_at,updated_at) VALUES('edit insider','inside-range.example','["10-100"]',1,1,1)`)
	f.save("inside-range.example", f.pid)
	f.enable()
	f.pool("192.0.2.131", "192.0.2.132")
	if !f.process(f.timeout("inside-range.example")) {
		t.Fatal(f.view())
	}
	op := f.view().Operations[0]
	g := splitTestGroups(f)
	a, b := splitEditValue(g[op.ChildAID]), splitEditValue(g[op.ChildBID])
	a.Host = "edited-insider-a.example"
	a.IDRange = "10-10"
	b.Host = "edited-insider-b.example"
	b.IDRange = "11-100"
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a, b}}); err != nil {
		t.Fatal(err)
	}
	entries, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Host == a.Host {
			found = true
			if !reflect.DeepEqual(e.UserIDs, []string{"10"}) {
				t.Fatal(e)
			}
		}
	}
	if !found {
		t.Fatal("edited insider singleton missing")
	}
}

func TestPostgresDispatchSplitReparentSubtreePreservesCooldown(t *testing.T) {
	f := newSplitIntegration(t)
	// Keep multiple actual accounts in the deepest leaf: singleton leaves now
	// intentionally stop all automation before creating a waiting quota record.
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at) SELECT id,'reparent-'||id||'@example.test','hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM unnest(ARRAY[20,21]) id`)
	f.pool("192.0.2.101", "192.0.2.102", "192.0.2.103", "192.0.2.104", "192.0.2.105", "192.0.2.106")
	c := f.timeout("range.example")
	f.enable()
	if !f.process(c) {
		t.Fatal(f.view())
	}
	first := f.view().Operations[0]
	child := f.timeout(first.IPA)
	f.exec(`UPDATE v2_dispatch_auto_split_operation SET updated_at=$1 WHERE status='succeeded'`, time.Now().Unix()-1201)
	f.exec(`UPDATE v2_dispatch_auto_split_cooldown SET last_success_at=$1`, time.Now().Unix()-1201)
	if !f.process(child) {
		t.Fatal(f.view())
	}
	second := f.view().Operations[0]
	groups := splitTestGroups(f)
	a := splitEditValue(groups[first.ChildAID])
	a.ParentGroupID = 0
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{a}}); err != nil {
		t.Fatal(err)
	}
	current := splitTestGroups(f)
	for _, id := range []int64{first.ChildAID, second.ChildAID, second.ChildBID} {
		if current[id].RootGroupID != first.ChildAID {
			t.Fatal("subtree root not propagated", current)
		}
	}
	var cooldown int64
	if err := f.db.QueryRow(`SELECT last_success_at FROM v2_dispatch_auto_split_cooldown WHERE root_group_id=$1`, first.ChildAID).Scan(&cooldown); err != nil || cooldown < time.Now().Unix()-10 {
		t.Fatal("cooldown reset by detach", cooldown, err)
	}
	next := f.timeout(second.IPA)
	if f.process(next) {
		t.Fatal("reparent bypassed quota")
	}
	found := false
	for _, op := range f.view().Operations {
		if op.Host == second.IPA && op.Status == "waiting" {
			found = true
			if op.RootGroupID != first.ChildAID {
				t.Fatal("waiting ledger uses stale root", op)
			}
		}
	}
	if !found {
		t.Fatal("missing waiting quota record")
	}
	current = splitTestGroups(f)
	bad := splitEditValue(current[first.ChildAID])
	bad.ParentGroupID = second.ChildAID
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{bad}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("cycle accepted", err)
	}
	// Moving an observed waiting child must also move its ledger root on retry.
	leaf := splitEditValue(current[second.ChildAID])
	leaf.ParentGroupID = first.GroupID
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{leaf}}); err != nil {
		t.Fatal(err)
	}
	if f.process(next) {
		t.Fatal("moving back bypassed cooldown")
	}
	for _, op := range f.view().Operations {
		if op.Host == second.IPA && op.Status == "waiting" && op.RootGroupID != first.GroupID {
			t.Fatal("reused waiting record kept old root", op)
		}
	}
	// Rejected graph mutation leaves the complete current graph intact.
	stable := f.view().Groups
	g := splitEditValue(splitTestGroups(f)[first.GroupID])
	g.ParentGroupID = g.ID
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{g}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal("self cycle accepted", err)
	}
	if !reflect.DeepEqual(stable, f.view().Groups) {
		t.Fatal("failed graph edit was partially applied")
	}
}

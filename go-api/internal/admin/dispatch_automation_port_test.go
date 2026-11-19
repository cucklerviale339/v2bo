package admin

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func (f *splitIntegration) setCheckPort(host string, port int64) {
	f.t.Helper()
	if err := f.s.SaveDispatchMonitor(f.ctx, DispatchMonitorSaveRequest{Host: host, CheckPort: port, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500, ProbeIDs: []int64{f.pid}}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *splitIntegration) healthyPoolPort(port int64, ips ...string) {
	f.t.Helper()
	items := []DispatchPoolSave{}
	for _, ip := range ips {
		items = append(items, DispatchPoolSave{IP: ip, Port: port, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500})
	}
	if _, err := f.s.SaveDispatchPool(f.ctx, items); err != nil {
		f.t.Fatal(err)
	}
	tasks, err := f.s.ListDispatchCheckTasks(f.ctx, f.pid)
	if err != nil {
		f.t.Fatal(err)
	}
	yes, latency := true, int64(5)
	for _, task := range tasks {
		for seq := 1; seq <= 2; seq++ {
			if _, err = f.s.ReportDispatchCheckResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: fmt.Sprintf("qa-%d", seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &latency}}}); err != nil {
				f.t.Fatal(err)
			}
		}
	}
}

func (f *splitIntegration) assertCheckPort(host string, port int64) {
	f.t.Helper()
	task, ok := f.tasks(f.pid)[host]
	if !ok || task.CheckPort != port || task.CheckIntervalSec != 30 || task.TCPTimeoutMS != 500 {
		f.t.Fatalf("wrong probe task for %s: %#v, want port %d", host, task, port)
	}
}

func (f *splitIntegration) addUpperHalfAccount() {
	f.t.Helper()
	// The range is 10-100, but the base fixture only has accounts below 55.
	// Probe tasks are emitted only for entries actually dispatched to an account.
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at)
VALUES(75,'upper-half@example.test','hash','00000000-0000-0000-0000-000000000075',lpad('75',32,'0'),1,1,1000000,1,1)`)
}

// Exercise allocation, actual subscription dispatch and the next generation,
// using ports different from both 443 and the fixture's original 18443.
func TestPostgresInvestigationPortAcrossAllocationPaths(t *testing.T) {
	for _, mode := range []string{"filter", "bisect", "no_pulls", "three_buckets"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			if mode == "no_pulls" {
				// Unknown future IDs still use the original range address after
				// the roster moves. Supply a second independent healthy control.
				f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','control','control.example','443',443,'1','tcp',1,1,1)`)
				f.save("control.example", f.pid)
				if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			g := f.group("range.example")
			f.setCheckPort(g.Host, 24443)
			f.healthyPoolPort(24443, "192.0.2.201", "192.0.2.202", "192.0.2.203")
			pulled := []int64{11, 12, 13}
			if mode == "bisect" {
				pulled = investigationGroupIDs(g)
			} else if mode == "no_pulls" {
				pulled = nil
			} else if mode == "three_buckets" {
				pulled = []int64{11, 12, 13, 14}
			}
			f.outage(g, pulled)
			if mode == "three_buckets" {
				// The first pair pulled earlier than T-120min, still in this round.
				f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2 WHERE id=$1`, g.ID, time.Now().Unix()-10000)
				for _, table := range []string{"v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent"} {
					f.exec(`UPDATE `+table+` SET delivered_at=$2 WHERE group_id=$1 AND user_id IN(11,12)`, g.ID, time.Now().Unix()-9000)
				}
			}
			f.execProcess(g.ID)
			if f.successfulEvents() != 1 {
				t.Fatal("allocation did not run", f.groups())
			}
			var next InvestigationGroup
			children := 0
			for _, child := range f.groups() {
				if child.ParentID != g.ID && child.ID != g.ID {
					continue
				}
				children++
				f.assertCheckPort(child.Host, 24443)
				for _, id := range investigationGroupIDs(child) {
					servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
					if err != nil || len(servers) == 0 || fmt.Sprint(servers[0]["host"]) != child.Host || fmt.Sprint(servers[0]["port"]) != "443" {
						t.Fatal("wrong actual address or subscription port", id, servers, err)
					}
				}
				if len(child.UserIDs) >= 4 {
					next = child
				}
			}
			wantChildren := map[string]int{"filter": 2, "bisect": 2, "no_pulls": 1, "three_buckets": 3}[mode]
			if children != wantChildren || next.ID == 0 {
				t.Fatal("wrong partitions", children, f.groups())
			}
			// A saved change on this child, rather than a browser preference,
			// becomes the source of truth for its next generation.
			f.setCheckPort(next.Host, 31443)
			f.execProcess(next.ID) // Config change starts a fresh observation round.
			f.healthyPoolPort(31443, "192.0.2.211", "192.0.2.212")
			f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind IN('filtered','bisected','no_pulls')`)
			f.outage(next, investigationGroupIDs(next))
			f.execProcess(next.ID)
			if f.successfulEvents() != 2 {
				t.Fatal("second generation did not run", f.groups())
			}
			for _, grandchild := range f.groups() {
				if grandchild.ParentID == next.ID {
					f.assertCheckPort(grandchild.Host, 31443)
				}
			}
		})
	}
}

func TestPostgresAutomationRejectsHealthyPoolOnWrongPort(t *testing.T) {
	for _, investigate := range []bool{false, true} {
		t.Run(fmt.Sprint(investigate), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			if !investigate {
				f.addUpperHalfAccount()
			}
			g := f.group("range.example")
			f.setCheckPort(g.Host, 24443)
			f.healthyPoolPort(443, "192.0.2.221", "192.0.2.222")
			f.outage(g, investigationGroupIDs(g))
			if !investigate {
				f.exec(`UPDATE v2_dispatch_investigation_settings SET enabled=FALSE; UPDATE v2_dispatch_investigation_group SET active=FALSE`)
				f.enable()
			}
			before := f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member", "v2_node_address_rule")
			if investigate {
				f.execProcess(g.ID)
				if f.successfulEvents() != 0 || !strings.Contains(f.group(g.Host).Reason, "同检测端口") {
					t.Fatal("wrong-port pool was allocated", f.groups())
				}
			} else if f.process(f.timeout(g.Host)) || !strings.Contains(f.view().Operations[0].Reason, "同检测端口") {
				t.Fatal("wrong-port pool was allocated", f.view())
			}
			if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member", "v2_node_address_rule")) {
				t.Fatal("port mismatch partially changed dispatch")
			}
			f.healthyPoolPort(24443, "192.0.2.223", "192.0.2.224")
			if investigate {
				f.execProcess(g.ID)
				if f.successfulEvents() != 1 {
					t.Fatal(f.groups())
				}
			} else if !f.process(f.timeout(g.Host)) {
				t.Fatal(f.view())
			}
			for _, host := range []string{"192.0.2.223", "192.0.2.224"} {
				f.assertCheckPort(host, 24443)
			}
		})
	}
}

func TestPostgresInvestigationNewEntryNeverHealthyDoesNotReallocate(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.231", "192.0.2.232", "192.0.2.233", "192.0.2.234")
	g := f.group("range.example")
	f.outage(g, investigationGroupIDs(g))
	f.execProcess(g.ID)
	var child InvestigationGroup
	for _, v := range f.groups() {
		if v.ParentID == g.ID {
			child = v
			break
		}
	}
	if child.ID == 0 {
		t.Fatal("missing child", f.groups())
	}
	f.execProcess(child.ID)
	f.timeout(child.Host) // No preceding success for this newly created monitor.
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='bisected'`)
	before := f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member")
	for i := 0; i < 3; i++ {
		f.execProcess(child.ID)
	}
	if f.successfulEvents() != 1 || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member")) || !strings.Contains(f.group(child.Host).Reason, "尚未确认正常") {
		t.Fatal("unhealthy new entry triggered another allocation", f.groups())
	}
}

func TestPostgresAutoSplitDescendantPortAndInitialFailureGuard(t *testing.T) {
	f := newSplitIntegration(t)
	f.addUpperHalfAccount()
	f.setCheckPort("range.example", 24443)
	f.healthyPoolPort(24443, "192.0.2.241", "192.0.2.242")
	f.enable()
	if !f.process(f.timeout("range.example")) {
		t.Fatal(f.view())
	}
	op := f.view().Operations[0]
	f.assertCheckPort(op.IPA, 24443)
	f.assertCheckPort(op.IPB, 24443)
	f.setCheckPort(op.IPA, 31443)
	f.healthyPoolPort(31443, "192.0.2.243", "192.0.2.244")
	f.exec(`UPDATE v2_dispatch_auto_split_operation SET updated_at=updated_at-1300 WHERE status='succeeded'; UPDATE v2_dispatch_auto_split_cooldown SET last_success_at=last_success_at-1300`)
	c := f.timeout(op.IPA)
	before := f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_node_address_rule")
	for i := 0; i < 3; i++ {
		if f.process(c) {
			t.Fatal("new address that never worked was split again")
		}
	}
	// A success from an older configuration cannot unlock the current port.
	f.exec(`INSERT INTO v2_dispatch_history(source,kind,target_id,host,port,probe_id,version,run_id,sequence,success,payload,created_at) VALUES('entry','sample',$1,$2,24443,$3,$4,$5,1,TRUE,'{}',$6)`, c.ID, c.Host, c.ProbeID, c.Version-1, c.RunID, time.Now().Unix()-700)
	if f.process(c) || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_node_address_rule")) {
		t.Fatal("old configuration success bypassed initial failure guard")
	}
	// Reparenting cannot erase the fact that this is an assigned address.
	groups := splitTestGroups(f)
	edit := splitEditValue(groups[op.ChildAID])
	edit.ParentGroupID = 0
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{edit}}); err != nil {
		t.Fatal(err)
	}
	if f.process(c) {
		t.Fatal("detaching bypassed initial failure guard")
	}
	if !f.process(f.confirmedTimeout(op.IPA)) || f.successes() != 2 {
		t.Fatal("valid later incident did not split", f.view())
	}
	next := f.view().Operations[0]
	f.assertCheckPort(next.IPA, 31443)
	f.assertCheckPort(next.IPB, 31443)
	groups = splitTestGroups(f)
	value := splitEditValue(groups[next.ChildAID])
	value.Host = "manually-edited.example"
	if err := f.s.EditDispatchSplitGroups(f.ctx, DispatchSplitEditRequest{Groups: []DispatchSplitGroupEdit{value}}); err != nil {
		t.Fatal(err)
	}
	f.assertCheckPort(value.Host, 31443)
}

func TestPostgresInvestigationManualAndMergedObservationPort(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.setCheckPort(g.Host, 24443)
	if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: g.Name, Host: "manual-port.example"}); err != nil {
		t.Fatal(err)
	}
	f.assertCheckPort("manual-port.example", 24443)
	g = f.group("manual-port.example")
	f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','control','control.example','443',443,'1','tcp',1,1,1)`)
	f.save("control.example", f.pid)
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.healthyPoolPort(24443, "192.0.2.245", "192.0.2.246", "192.0.2.247")
	f.outage(g, []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	var candidate, observation InvestigationGroup
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			f.assertCheckPort(child.Host, 24443)
			if child.Kind == "observation" {
				observation = child
			} else {
				candidate = child
			}
		}
	}
	if candidate.ID == 0 || observation.ID == 0 {
		t.Fatal(f.groups())
	}
	f.execProcess(observation.ID)
	f.exec(`UPDATE v2_dispatch_investigation_group SET ready_at=$1,epoch_at=$1 WHERE id=$2`, time.Now().Unix()-1200, observation.ID)
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
	f.outage(candidate, []int64{11, 12})
	f.execProcess(candidate.ID)
	if f.successfulEvents() != 2 || len(f.group(observation.Host).UserIDs) != 6 {
		t.Fatal("healthy same-port observation did not merge", f.groups())
	}
	for _, child := range f.groups() {
		if child.RootID == g.RootID {
			f.assertCheckPort(child.Host, 24443)
		}
	}
}

func TestPostgresInvestigationAllocationRollbackAndConcurrentRetry(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.251", "192.0.2.252")
	g := f.group("range.example")
	f.outage(g, investigationGroupIDs(g))
	f.exec(`CREATE FUNCTION reject_second_allocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.host='192.0.2.252' THEN RAISE EXCEPTION 'injected allocation failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_second_allocation BEFORE INSERT ON v2_dispatch_monitor FOR EACH ROW EXECUTE FUNCTION reject_second_allocation()`)
	before := f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_check_target", "v2_node_address_rule")
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_check_target", "v2_node_address_rule")) || !strings.Contains(f.group(g.Host).Reason, "本轮未修改") {
		t.Fatal("failed second allocation left a partial switch", f.groups())
	}
	f.exec(`DROP TRIGGER reject_second_allocation ON v2_dispatch_monitor`)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- f.s.processInvestigation(f.ctx, g.ID)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.successfulEvents() != 1 {
		t.Fatal("concurrent retries duplicated allocation", f.groups())
	}
	children := 0
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			children++
			f.assertCheckPort(child.Host, 18443)
		}
	}
	if children != 2 {
		t.Fatal("wrong child count", f.groups())
	}
}

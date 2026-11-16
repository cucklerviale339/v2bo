package admin

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
)

func (f *investigationIntegration) soleObserver() (InvestigationGroup, InvestigationGroup) {
	f.t.Helper()
	g := f.group("range.example")
	ids := []int64{}
	for _, id := range investigationGroupIDs(g) {
		if id != 17 {
			ids = append(ids, id)
		}
	}
	f.outage(g, ids)
	f.execProcess(g.ID)
	var observer, candidate InvestigationGroup
	for _, child := range f.groups() {
		if child.ParentID != g.ID {
			continue
		}
		if child.Kind == "observation" {
			observer = child
		} else {
			candidate = child
		}
	}
	if observer.ID == 0 || !reflect.DeepEqual(observer.UserIDs, []string{"17"}) || observer.ManualOnly || observer.Host == g.Host || observer.Name != "观察" {
		f.t.Fatal("non-recipient was accused or stranded", f.groups())
	}
	f.assertCheckPort(observer.Host, 18443)
	f.assertUserHosts(17, observer.Host)
	return observer, candidate
}

func TestPostgresInvestigationSoleObserverScreensEachNewRound(t *testing.T) {
	for _, pulled := range []bool{false, true} {
		t.Run(map[bool]string{false: "no_pulls", true: "pulled_later"}[pulled], func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
			observer, candidate := f.soleObserver()
			f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
			ids := []int64{}
			if pulled {
				ids = []int64{17}
			}
			f.outage(observer, ids)
			f.execProcess(observer.ID)
			var after InvestigationGroup
			for _, x := range f.groups() {
				if reflect.DeepEqual(x.UserIDs, observer.UserIDs) {
					after = x
				}
			}
			if pulled {
				if after.Kind != "confirmed" || !after.ManualOnly || after.Host != observer.Host || after.Name != "实锤内鬼" {
					t.Fatal("new-round sole recipient was permanently exempted", after)
				}
				f.assertUserHosts(17, observer.Host)
				f.assertUserHosts(11, candidate.Host)
				before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")
				f.execProcess(after.ID)
				if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
					t.Fatal("confirmed singleton continued automatic processing")
				}
				return
			}
			if after.Kind != "observation" || after.ManualOnly || after.Host == observer.Host || !reflect.DeepEqual(after.UserIDs, observer.UserIDs) {
				t.Fatal("sole observer cannot fail over", after)
			}
			f.assertUserHosts(17, after.Host)
			f.assertUserHosts(11, candidate.Host)
			f.assertCheckPort(after.Host, 18443)
			if err := f.s.EditInvestigation(f.ctx, InvestigationEdit{ID: after.ID, Revision: after.Revision, Host: after.Host, Name: "观察自定义", Policy: "smart"}); err != nil {
				t.Fatal("editor forced observer to manual", err)
			}
		})
	}
}

func TestPostgresInvestigationSoleObserverMergesWithoutExtraPoolIP(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12})
	f.execProcess(g.ID)
	var observer, candidate InvestigationGroup
	for _, x := range f.groups() {
		if x.ParentID == g.ID {
			if x.Kind == "observation" {
				observer = x
			} else {
				candidate = x
			}
		}
	}
	f.execProcess(observer.ID)
	f.exec(`UPDATE v2_dispatch_investigation_group SET ready_at=$2,epoch_at=$2 WHERE id=$1`, observer.ID, time.Now().Unix()-1200)
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
	f.outage(candidate, []int64{11})
	f.execProcess(candidate.ID)
	merged := f.group(observer.Host)
	if len(merged.UserIDs) != 7 {
		t.Fatal("one non-recipient did not merge", f.groups())
	}
	f.assertUserHosts(12, observer.Host)
	for _, x := range f.groups() {
		if x.Kind == "confirmed" && (!reflect.DeepEqual(x.UserIDs, []string{"11"}) || !x.ManualOnly) {
			t.Fatal("candidate guard changed", x)
		}
	}
}

func TestPostgresInvestigationSoleObserverIgnoresPullAfterFailure(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
	g, _ := f.soleObserver()
	f.outage(g, nil)
	g = f.group(g.Host)
	f.exec(`INSERT INTO v2_dispatch_investigation_delivery(group_id,generation,user_id,delivered_at) VALUES($1,$2,17,$3)`, g.ID, g.Generation, time.Now().Unix()-1)
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
	f.execProcess(g.ID)
	after := f.group("192.0.2.203")
	if after.Kind != "observation" || after.ManualOnly || !reflect.DeepEqual(after.UserIDs, []string{"17"}) {
		t.Fatal("post-failure pull changed the screening cutoff", after)
	}
}

func TestPostgresInvestigationSoleObserverPoolWaitIsAtomic(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201") // Both candidate and observer need healthy entrances.
	g := f.group("range.example")
	ids := investigationGroupIDs(g)
	f.outage(g, ids[:len(ids)-1])
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
		t.Fatal("partial partition committed without enough IPs")
	}
	f.pool("192.0.2.202")
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("pool refill did not resume", f.groups())
	}
}

func TestPostgresInvestigationSoleObserverRecoveryMergeRespectsPolicy(t *testing.T) {
	for _, failoverOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "smart_merge", true: "failover_keeps_policy"}[failoverOnly], func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
			observer, target := f.soleObserver()
			// A compatible sibling observation group has already become healthy.
			f.exec(`UPDATE v2_dispatch_investigation_group SET kind='observation',name='观察' WHERE id=$1`, target.ID)
			if failoverOnly {
				f.exec(`UPDATE v2_dispatch_investigation_group SET policy='failover' WHERE id=$1`, observer.ID)
			}
			f.outage(observer, nil)
			f.execProcess(target.ID)
			f.exec(`UPDATE v2_dispatch_investigation_group SET ready_at=$2,epoch_at=$2 WHERE id=$1`, target.ID, time.Now().Unix()-1200)
			f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
			f.execProcess(observer.ID)
			if failoverOnly {
				after := f.group("192.0.2.203")
				if after.ID != observer.ID || after.Policy != "failover" || len(after.UserIDs) != 1 {
					t.Fatal("failover-only policy was lost during recovery", after)
				}
				f.assertUserHosts(17, after.Host)
				f.assertUserHosts(11, target.Host)
			} else {
				after := f.group(target.Host)
				if after.ID != target.ID || len(after.UserIDs) != 8 {
					t.Fatal("whole observer failed to merge into healthy sibling", f.groups())
				}
				for _, x := range f.groups() {
					if x.ID == observer.ID {
						t.Fatal("merged source group remained active", x)
					}
				}
				f.assertUserHosts(17, target.Host)
			}
		})
	}
}

func TestPostgresInvestigationSoleObserverManualActions(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
	g, _ := f.soleObserver()
	f.outage(g, nil)
	g = f.group(g.Host)
	if err := f.s.ConfirmInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
		t.Fatal("single observer confirm blocked", err)
	}
	g = f.group(g.Host)
	if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
		t.Fatal("single observer trigger blocked", err)
	}
	after := f.group("192.0.2.203")
	if after.Kind != "observation" || after.ManualOnly {
		t.Fatal(after)
	}
}

// Reproduce the old three-person partition: two recipients and one observer
// mislabeled as confirmed and left on the failed source monitor with ready=0.
func (f *investigationIntegration) legacyMislabeledObserver() InvestigationGroup {
	f.t.Helper()
	g := f.group("range.example")
	f.exec(`UPDATE v2_dispatch_investigation_group SET active=FALSE WHERE id=$1`, g.ID)
	var child int64
	at := time.Now().Unix() - 4000
	err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,name,kind,host,monitor_id,manual_only,epoch_at,created_at,reason) VALUES($1,$1,'实锤内鬼','confirmed',$2,$3,TRUE,$4,$4,'自动产生单人组，仅人工操作') RETURNING id`, g.ID, g.Host, g.MonitorID, at).Scan(&child)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE v2_dispatch_investigation_member SET group_id=$2 WHERE group_id=$1 AND user_id=17`, g.ID, child)
	part := []investigationPartition{{IDs: []int64{17}, Kind: "confirmed", Host: g.Host, GroupID: child}}
	raw, _ := json.Marshal(map[string]any{"before": g, "partitions": part, "unpulled_ids": []int64{17}, "pulled_ids": []int64{11, 12}})
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,first_failure_at,created_at,payload) VALUES($1,$1,'filtered',$2,$3,$4)`, g.ID, at-630, at, string(raw))
	for _, x := range f.groups() {
		if x.ID == child {
			return x
		}
	}
	f.t.Fatal("missing legacy observer")
	return InvestigationGroup{}
}

func TestPostgresInvestigationObserverUpgradeCompletesPendingAllocation(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201")
	g := f.legacyMislabeledObserver()
	// A later receipt must not rewrite the original unpulled partition.
	f.exec(`INSERT INTO v2_dispatch_investigation_delivery(group_id,generation,user_id,delivered_at) VALUES($1,$2,17,$3)`, g.ID, g.Generation, time.Now().Unix()-1)
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	corrected := f.group(g.Host)
	if corrected.Kind != "observation" || corrected.ManualOnly || !corrected.ObservationRepairPending {
		t.Fatal("mislabel not corrected", corrected)
	}
	f.execProcess(corrected.ID) // Configure the monitor without inventing health.
	f.timeout(g.Host)           // All failed reports, never a baseline for the child.
	f.execProcess(corrected.ID)
	after := f.group("192.0.2.201")
	if after.ID != g.ID || after.Kind != "observation" || after.ObservationRepairPending || after.ManualOnly {
		t.Fatal("legacy observer stranded", after)
	}
	f.assertUserHosts(17, after.Host)
	var events int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='observation_repaired'`, g.ID).Scan(&events)
	if events != 1 {
		t.Fatal("missing repair audit", events)
	}
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	if f.group(after.Host).ObservationRepairPending {
		t.Fatal("repair replayed")
	}
}

func TestPostgresInvestigationObserverUpgradeRespectsEditsAndEvidence(t *testing.T) {
	for _, mode := range []string{"edited", "recipient", "wrong_host", "missing_user", "deleted_monitor"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.legacyMislabeledObserver()
			switch mode {
			case "edited":
				f.exec(`UPDATE v2_dispatch_investigation_group SET revision=2 WHERE id=$1`, g.ID)
			case "recipient":
				f.exec(`UPDATE v2_dispatch_investigation_event SET payload=jsonb_set(payload,'{unpulled_ids}','[]') WHERE group_id=$1 AND kind='filtered'`, g.ParentID)
			case "wrong_host":
				f.exec(`UPDATE v2_dispatch_investigation_group SET host='changed.example' WHERE id=$1`, g.ID)
			case "missing_user":
				f.exec(`DELETE FROM v2_user WHERE id=17`)
			case "deleted_monitor":
				f.exec(`UPDATE v2_dispatch_monitor SET deleted=TRUE WHERE id=$1`, g.MonitorID)
			}
			if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
				t.Fatal(err)
			}
			for _, x := range f.groups() {
				if x.ID != g.ID {
					continue
				}
				if x.Kind == "confirmed" {
					t.Fatal("unsupported historical label survived", x)
				}
				if mode == "recipient" {
					if x.ManualOnly || !x.ObservationRepairPending {
						t.Fatal("untouched recipient singleton cannot resume observation", x)
					}
				} else if !x.ManualOnly || x.ObservationRepairPending {
					t.Fatal("changed/deleted group was automatically resumed", x)
				}
			}
		})
	}
}

func TestPostgresInvestigationObserverUpgradeWaitsForPoolAndLimit(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.legacyMislabeledObserver()
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	f.timeout(g.Host)
	f.execProcess(g.ID)
	after := f.group(g.Host)
	if !after.ObservationRepairPending {
		t.Fatal("pool absence discarded pending repair", after)
	}
	f.pool("192.0.2.201")
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=$2 WHERE group_id=$1 AND kind='filtered'`, g.ParentID, time.Now().Unix())
	f.execProcess(g.ID)
	if !f.group(g.Host).ObservationRepairPending {
		t.Fatal("repair bypassed cooldown")
	}
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE group_id=$1 AND kind='filtered'`, g.ParentID)
	f.execProcess(g.ID)
	if f.group("192.0.2.201").ObservationRepairPending {
		t.Fatal("pending repair did not resume")
	}
}

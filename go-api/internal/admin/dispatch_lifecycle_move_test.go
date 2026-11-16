package admin

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func (f *investigationIntegration) addSharedBusinessEndpoint(host string, monitor int64, user int64) int64 {
	f.t.Helper()
	f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(8,'[1]','other business','other.example','8443',8443,'1','tcp',1,1,1)`)
	var group int64
	if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_group(root_id,name,kind,host,monitor_id,epoch_at,created_at) VALUES(0,'other business','candidate',$1,$2,1,1) RETURNING id`, host, monitor).Scan(&group); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE v2_dispatch_investigation_group SET root_id=id WHERE id=$1`, group)
	f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,group_id,origin_host,user_id) VALUES($1,$1,'other.example',$2)`, group, user)
	return group
}

func TestPostgresLifecycleCorrectionPreservesSharedEndpointBusiness(t *testing.T) {
	for _, role := range []string{"stable", "whitelist"} {
		t.Run(role, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			_, stage := f.stageWithHistoricalRisk(role)
			other := f.addSharedBusinessEndpoint(stage.Host, stage.MonitorID, 11)
			// A single user may have multiple origins in the stage itself too.
			f.exec(`INSERT INTO v2_server_vmess(id,group_id,name,host,port,server_port,rate,network,"show",created_at,updated_at) VALUES(9,'[1]','extra scope','extra.example','9443',9443,'1','tcp',1,1,1)`)
			f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,group_id,origin_host,user_id) VALUES($1,$2,'extra.example',11)`, stage.RootID, stage.ID)
			f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$2,'edited',$3,'{"added_ids":[12]}')`, stage.RootID, stage.ID, time.Now().Unix())
			f.exec(`UPDATE v2_dispatch_check_target SET enabled=FALSE WHERE kind='pool'`)
			f.poolAtPort(23130, "192.0.2.213")
			var retained string
			if err := f.db.QueryRow(`SELECT jsonb_agg(to_jsonb(d) ORDER BY origin_host,user_id)::text FROM v2_dispatch_stability_receipt d WHERE user_id IN(12,13,14)`).Scan(&retained); err != nil {
				t.Fatal(err)
			}
			// Any error after the member transfer must roll back monitors,
			// assignments, receipt deletion and promotion holds together.
			tables := []string{"v2_dispatch_investigation_member", "v2_dispatch_stability_receipt", "v2_dispatch_monitor", "v2_dispatch_monitor_probe", "v2_dispatch_risk_case", "v2_dispatch_risk_member"}
			before := f.snapshot(tables...)
			f.exec(`ALTER TABLE v2_dispatch_investigation_event ADD CONSTRAINT reject_scoped_correction CHECK(kind<>'stage_corrected')`)
			f.execProcess(stage.ID)
			if !reflect.DeepEqual(before, f.snapshot(tables...)) {
				t.Fatal("failed correction changed dispatch, progress or audit")
			}
			// Ordinary monitoring may import historical observations after a
			// deferred correction, but must never record a successful transfer.
			var corrected int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='stage_corrected'`).Scan(&corrected); err != nil || corrected != 0 {
				t.Fatal("failed correction recorded success", corrected, err)
			}
			f.exec(`ALTER TABLE v2_dispatch_investigation_event DROP CONSTRAINT reject_scoped_correction`)
			stage = f.group(stage.Host)
			f.execProcess(stage.ID)
			after := f.group(stage.Host)
			if !reflect.DeepEqual(after.UserIDs, []string{"12", "13", "14"}) || after.NormalSince != stage.NormalSince || after.EpochAt != stage.EpochAt || after.Generation != stage.Generation || !reflect.DeepEqual(after.NormalCheckpoints, stage.NormalCheckpoints) {
				t.Fatal("retained roster/progress changed", after)
			}
			var target InvestigationGroup
			for _, g := range f.groups() {
				if g.ParentID == stage.ID && g.LifecycleRole == "ordinary" {
					target = g
				}
			}
			if target.ID == 0 || target.Host != "192.0.2.213" || target.Name != "待复核" || !target.RosterFrozen || !reflect.DeepEqual(target.UserIDs, []string{"11"}) {
				t.Fatal("correction did not complete", f.groups())
			}
			f.assertUserHosts(11, target.Host, stage.Host)
			f.assertCheckPort(target.Host, 23130)
			f.assertCheckPort(stage.Host, 18443)
			var untouched, moved int
			f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id=11 AND origin_host='other.example'`, other).Scan(&untouched)
			f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id=11`, target.ID).Scan(&moved)
			if untouched != 1 || moved != 2 {
				t.Fatal("business assignment was broadened", untouched, moved)
			}
			var receipts string
			if err := f.db.QueryRow(`SELECT jsonb_agg(to_jsonb(d) ORDER BY origin_host,user_id)::text FROM v2_dispatch_stability_receipt d WHERE user_id IN(12,13,14)`).Scan(&receipts); err != nil || receipts != retained {
				t.Fatal("retained receipts changed", err)
			}
			u := usersvc.NewDBService(f.s.cfg, f.db)
			nodes, err := u.Servers(f.ctx, 11, "")
			if err != nil || len(nodes) != 3 {
				t.Fatal(nodes, err)
			}
			for _, n := range nodes {
				host := target.Host
				if n["name"] == "other business" {
					host = stage.Host
				}
				if fmt.Sprint(n["host"]) != host {
					t.Fatal("rendered subscription differs", nodes)
				}
			}
			tx, err := f.db.BeginTx(f.ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			held, err := investigationPromotionHeld(f.ctx, tx, target.ID)
			pending, e := investigationStageCorrectionIDs(f.ctx, tx, after)
			tx.Rollback()
			if err != nil || e != nil || !held || len(pending) != 0 {
				t.Fatal("hold or retry state incorrect", held, pending, err, e)
			}
			f.execProcess(stage.ID)
			var events int
			if err = f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='stage_corrected'`).Scan(&events); err != nil || events != 1 {
				t.Fatal("correction repeated", events, err)
			}
		})
	}
}

func TestPostgresLifecyclePromotionPreservesSharedEndpointBusiness(t *testing.T) {
	for _, role := range []string{"stable", "whitelist"} {
		t.Run(role, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.enableLifecycle()
			f.pool("192.0.2.211", "192.0.2.212")
			g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
			if role == "whitelist" {
				f.execProcess(g.ID)
				g = f.readyToPromote(f.stageGroup("stable"), []int64{11, 12, 13, 14})
			}
			other := f.addSharedBusinessEndpoint(g.Host, g.MonitorID, 11)
			f.execProcess(g.ID)
			target := f.stageGroup(role)
			if !reflect.DeepEqual(target.UserIDs, []string{"11", "12", "13", "14"}) || target.Host == g.Host {
				t.Fatal("promotion did not complete", target)
			}
			f.assertUserHosts(11, g.Host, target.Host)
			var count int
			if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_member WHERE group_id=$1 AND origin_host='other.example' AND user_id=11`, other).Scan(&count); err != nil || count != 1 {
				t.Fatal("other business changed", count, err)
			}
		})
	}
}

func TestPostgresLifecycleBusinessMoveRejectsUnrelatedAssignmentChange(t *testing.T) {
	f := newInvestigationIntegration(t)
	_, stage := f.stageWithHistoricalRisk("stable")
	other := f.addSharedBusinessEndpoint(stage.Host, stage.MonitorID, 11)
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before, err := usersvc.DispatchEntriesFrom(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planInvestigationBusinessMove(f.ctx, tx, stage.ID, []int64{11})
	if err != nil {
		t.Fatal(err)
	}
	// Change only ownership to another group at the SAME address. A host-only
	// comparison would miss this unrelated business transfer entirely.
	if _, err = tx.Exec(`UPDATE v2_dispatch_investigation_member SET group_id=$1 WHERE group_id=$2 AND user_id=11`, other, stage.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE v2_dispatch_investigation_member SET group_id=$1 WHERE group_id=$2 AND origin_host='other.example' AND user_id=11`, stage.ID, other); err != nil {
		t.Fatal(err)
	}
	after, err := usersvc.DispatchEntriesFrom(f.ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	err = plan.verify(f.ctx, tx, before, after, InvestigationGroup{ID: other, Host: stage.Host, Generation: 1})
	if err == nil || !strings.Contains(err.Error(), "业务下发关系") {
		t.Fatal("unrelated same-host transfer accepted", err)
	}
}

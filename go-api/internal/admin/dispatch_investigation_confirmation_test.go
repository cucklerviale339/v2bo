package admin

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
)

func TestPostgresInvestigationConfirmationBisectedSingletonsNeedNewRounds(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203", "192.0.2.204")
	g := f.group("range.example")
	f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id NOT IN(11,12)`, g.ID)
	g = f.group(g.Host)
	f.outage(g, []int64{11, 12})
	f.execProcess(g.ID)
	children := []InvestigationGroup{}
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			children = append(children, child)
			if len(child.UserIDs) != 1 || child.Kind == "confirmed" || child.ManualOnly || child.Host == g.Host {
				t.Fatal("bisection size fabricated a confirmation", child)
			}
			f.assertCheckPort(child.Host, 18443)
		}
	}
	if len(children) != 2 || children[0].Host == children[1].Host {
		t.Fatal(children)
	}
	// Only a new healthy entrance, its own recipient and a later confirmed
	// fault establish the singleton. A sibling cannot inherit that finding.
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='bisected'`)
	c := children[0]
	f.outage(c, investigationGroupIDs(c))
	f.execProcess(c.ID)
	var confirmed InvestigationGroup
	for _, x := range f.groups() {
		if x.Kind == "confirmed" {
			confirmed = x
		}
	}
	if !reflect.DeepEqual(confirmed.UserIDs, c.UserIDs) || confirmed.Host != c.Host || !confirmed.ManualOnly || len(confirmed.ConfirmationProof) < 5 {
		t.Fatal("healthy sole-recipient round was not confirmed", confirmed)
	}
	var unresolved int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_risk_case WHERE resolved_event_id=0`).Scan(&unresolved)
	if unresolved != 0 {
		t.Fatal("child proof did not resolve related ancestor cases", unresolved)
	}
	if f.group(children[1].Host).PromotionBlockedCount != 0 || confirmed.PromotionBlockedCount != 1 {
		t.Fatal("resolution failed to distinguish the confirmed user from siblings", confirmed, f.group(children[1].Host))
	}
	f.assertUserHosts(investigationGroupIDs(children[1])[0], children[1].Host)
}

func TestPostgresInvestigationConfirmationUnrelatedCaseAndFreshObservation(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	raw, _ := json.Marshal(map[string]any{"before": g, "pulled_ids": []int64{11, 12}, "unpulled_ids": []int64{13, 14}})
	// Same user in a distinct business case cannot clear this entrance case.
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES(999,999,'filtered',$1,$2)`, time.Now().Unix()-10000, string(raw))
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	f.outage(g, []int64{11})
	f.exec(`INSERT INTO v2_dispatch_stability_receipt(origin_host,user_id,host,first_at,last_at) VALUES('range.example',12,$1,$2,$2) ON CONFLICT(origin_host,user_id) DO UPDATE SET first_at=EXCLUDED.first_at`, g.Host, time.Now().Unix()-90000)
	f.execProcess(g.ID)
	var unresolved int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_risk_case WHERE resolved_event_id=0`).Scan(&unresolved)
	if unresolved != 1 {
		t.Fatal("proof cleared an unrelated business incident", unresolved)
	}
	var resolvedAt int64
	f.db.QueryRow(`SELECT max(resolved_at) FROM v2_dispatch_risk_case WHERE resolved_event_id>0`).Scan(&resolvedAt)
	if resolvedAt < time.Now().Unix()-10 {
		t.Fatal("release did not establish a new observation boundary", resolvedAt)
	}
	var firstAt int64
	if err := f.db.QueryRow(`SELECT first_at FROM v2_dispatch_stability_receipt WHERE origin_host='range.example' AND user_id=12`).Scan(&firstAt); err != nil || firstAt >= resolvedAt {
		t.Fatal("non-recipient observation was reset by a later proof", firstAt, resolvedAt, err)
	}
}

func TestPostgresInvestigationConfirmationHistoryCategoryPagination(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	for _, kind := range []string{"filtered", "stable_promoted", "edited"} {
		f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) SELECT $1,$1,$2,EXTRACT(EPOCH FROM clock_timestamp())::bigint,'{}'::jsonb FROM generate_series(1,25)`, g.ID, kind)
	}
	for _, category := range []string{"screening", "lifecycle"} {
		first, err := f.s.GetInvestigationCategory(f.ctx, 1, category)
		if err != nil || first.Total != 25 || len(first.Events) != 20 {
			t.Fatal(category, first.Total, len(first.Events), err)
		}
		second, err := f.s.GetInvestigationCategory(f.ctx, 2, category)
		if err != nil || second.Total != 25 || len(second.Events) != 5 {
			t.Fatal(category, second.Total, len(second.Events), err)
		}
		if first.Events[len(first.Events)-1].ID <= second.Events[0].ID {
			t.Fatal("pagination overlapped")
		}
	}
}

func TestPostgresInvestigationConfirmationRecentAndOlderSingletonsAreNotProof(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12})
	// Both are successful recipients of this same entrance round. Different
	// 120-minute buckets cannot turn either of them into the only recipient.
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=epoch_at-10000,ready_at=ready_at-10000 WHERE id=$1`, g.ID)
	f.exec(`UPDATE v2_dispatch_investigation_delivery SET delivered_at=delivered_at-8000 WHERE group_id=$1 AND user_id=12`, g.ID)
	f.exec(`UPDATE v2_dispatch_investigation_delivery_recent SET delivered_at=delivered_at-8000 WHERE group_id=$1 AND user_id=12`, g.ID)
	f.execProcess(g.ID)
	count := 0
	for _, x := range f.groups() {
		if x.ParentID == g.ID {
			count++
			if x.Kind == "confirmed" || x.ManualOnly || x.Host == g.Host {
				t.Fatal("time bucket created false proof", x)
			}
		}
	}
	if count != 3 {
		t.Fatal(f.groups())
	}
}

func TestPostgresInvestigationConfirmationSoleRecipientAndNoPull(t *testing.T) {
	for _, mode := range []string{"sole", "unpulled", "after_failure", "incomplete", "outside", "no_baseline", "healthy_after_pull", "short_manual", "manual_config_change"} {
		t.Run(mode, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.201", "192.0.2.202")
			g := f.group("range.example")
			ids := []int64{11}
			if mode == "unpulled" || mode == "after_failure" {
				ids = nil
			}
			f.outage(g, ids)
			g = f.group(g.Host)
			switch mode {
			case "after_failure":
				f.exec(`INSERT INTO v2_dispatch_investigation_delivery VALUES($1,$2,11,$3)`, g.ID, g.Generation, time.Now().Unix()-1)
			case "incomplete":
				f.exec(`UPDATE v2_dispatch_investigation_health SET delivery_failure_at=$1`, time.Now().Unix()-1)
			case "outside":
				f.exec(`INSERT INTO v2_dispatch_host_exposure VALUES($1,999999,$2,$2)`, g.Host, time.Now().Unix()-650)
			case "no_baseline":
				f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(payload,'{success}','false') WHERE target_id=$1 AND source='entry'`, g.MonitorID)
			case "healthy_after_pull":
				f.exec(`UPDATE v2_dispatch_investigation_group SET ready_at=EXTRACT(EPOCH FROM clock_timestamp())::bigint-700 WHERE id=$1`, g.ID)
				f.exec(`UPDATE v2_dispatch_investigation_delivery SET delivered_at=delivered_at-100 WHERE group_id=$1`, g.ID)
				f.exec(`UPDATE v2_dispatch_investigation_delivery_recent SET delivered_at=delivered_at-100 WHERE group_id=$1`, g.ID)
			case "manual_config_change":
				f.exec(`UPDATE v2_dispatch_investigation_group SET config_key='old-monitor-configuration' WHERE id=$1`, g.ID)
			case "short_manual":
				f.exec(`UPDATE v2_dispatch_history SET created_at=created_at+450,payload=jsonb_set(payload,'{reported_at}',to_jsonb((payload->>'reported_at')::bigint+450)) WHERE target_id=$1 AND source='entry' AND created_at<$2`, g.MonitorID, time.Now().Unix()-450)
			}
			if mode == "no_baseline" || mode == "short_manual" || mode == "manual_config_change" {
				if err := f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}); err != nil {
					t.Fatal(err)
				}
			} else {
				f.execProcess(g.ID)
			}
			confirmed := 0
			for _, x := range f.groups() {
				if x.Kind == "confirmed" {
					confirmed++
					if !reflect.DeepEqual(x.UserIDs, []string{"11"}) || !x.ManualOnly || x.Host != g.Host {
						t.Fatal(x)
					}
				}
			}
			if (confirmed == 1) != (mode == "sole") {
				t.Fatal("wrong confirmation", mode, f.groups())
			}
			if mode == "sole" {
				var unresolved int
				f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_risk_case WHERE resolved_event_id=0`).Scan(&unresolved)
				if unresolved != 0 {
					t.Fatal("valid confirmation did not resolve its case")
				}
			}
		})
	}
}

func TestPostgresInvestigationConfirmationOriginalSingleton(t *testing.T) {
	for _, pulled := range []bool{false, true} {
		t.Run(map[bool]string{false: "unpulled", true: "sole_recipient"}[pulled], func(t *testing.T) {
			f := newInvestigationIntegration(t)
			// Keep both independent control users, but only one actual user of
			// the original range entrance. No previous screening is involved.
			f.exec(`DELETE FROM v2_user WHERE id NOT IN(5,11,150)`)
			g := f.group("range.example")
			if g.ParentID != 0 || !reflect.DeepEqual(g.UserIDs, []string{"11"}) || g.ManualOnly {
				t.Fatal("original singleton was disabled before any evidence", g)
			}
			f.pool("192.0.2.221")
			ids := []int64{}
			if pulled {
				ids = []int64{11}
			}
			f.outage(g, ids)
			f.execProcess(g.ID)
			var result InvestigationGroup
			for _, x := range f.groups() {
				if x.Active && reflect.DeepEqual(x.UserIDs, []string{"11"}) {
					result = x
				}
			}
			if result.ID == 0 {
				t.Fatal("original singleton lost its assignment", f.groups())
			}
			if pulled {
				if result.Kind != "confirmed" || !result.ManualOnly || result.Name != "实锤内鬼" || result.Host != g.Host || len(result.ConfirmationProof) < 5 {
					t.Fatal("original sole recipient was not confirmed", result)
				}
				before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event")
				f.execProcess(result.ID)
				if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event")) {
					t.Fatal("confirmed original singleton continued automation")
				}
			} else if result.Kind == "confirmed" || result.ManualOnly || result.Host == g.Host {
				t.Fatal("unpulled original singleton was accused or stranded", result)
			}
			f.assertUserHosts(11, result.Host)
			f.assertCheckPort(result.Host, 18443)
			var nodePort string
			if err := f.db.QueryRow(`SELECT port FROM v2_server_vmess WHERE id=7`).Scan(&nodePort); err != nil || nodePort != "443" {
				t.Fatal("detection port overwrote the business node port", nodePort, err)
			}
		})
	}
}

func TestPostgresInvestigationConfirmationLegacyPulledSingletonNotTrusted(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.legacyMislabeledObserver()
	f.exec(`UPDATE v2_dispatch_investigation_event SET payload=jsonb_set(payload,'{pulled_ids}','[11,12,17]') WHERE group_id=$1 AND kind='filtered'`, g.ParentID)
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	got := f.group(g.Host)
	if got.Kind == "confirmed" || got.ManualOnly || !got.ObservationRepairPending || got.Host != g.Host {
		t.Fatal("legacy recipient singleton was trusted", got)
	}
	var resolved int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_risk_case WHERE resolved_event_id<>0`).Scan(&resolved)
	if resolved != 0 {
		t.Fatal("legacy false label resolved history")
	}
	before := f.snapshot("v2_dispatch_risk_case", "v2_dispatch_risk_member", "v2_dispatch_investigation_group", "v2_dispatch_investigation_event")
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_risk_case", "v2_dispatch_risk_member", "v2_dispatch_investigation_group", "v2_dispatch_investigation_event")) {
		t.Fatal("migration replayed")
	}
}

func TestPostgresInvestigationConfirmationRiskSurvivesPromotionAndHistoryCategories(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.enableLifecycle()
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.readyToPromote(f.group("range.example"), []int64{11, 12, 13, 14})
	f.execProcess(g.ID)
	stable := f.stageGroup("stable")
	stable = f.readyToPromote(stable, []int64{11, 12, 13, 14})
	// Backfill a historical screening episode whose users have already moved
	// into a shared stage. Mutable root/host and dormant time cannot clear it.
	raw, _ := json.Marshal(map[string]any{"before": g, "pulled_ids": []int64{11, 12}, "unpulled_ids": []int64{13, 14}})
	f.exec(`INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) VALUES($1,$1,'filtered',$2,$3)`, g.ID, time.Now().Unix()-90000, string(raw))
	if err := postgres.EnsureNodeAddressSchema(f.ctx, f.db); err != nil {
		t.Fatal(err)
	}
	f.execProcess(stable.ID)
	for _, x := range f.groups() {
		if x.LifecycleRole == "whitelist" {
			t.Fatal("unresolved history admitted dormant users", x)
		}
	}
	var corrected InvestigationGroup
	for _, x := range f.groups() {
		if x.ParentID == stable.ID && x.LifecycleRole == "ordinary" {
			corrected = x
		}
	}
	if corrected.ID == 0 || corrected.Host == stable.Host || corrected.PromotionBlockedCount != 2 || len(corrected.UserIDs) != 2 {
		t.Fatal("historical stage risk was not isolated", f.groups())
	}
	for _, category := range []string{"screening", "lifecycle", "management"} {
		v, err := f.s.GetInvestigationCategory(f.ctx, 1, category)
		if err != nil || v.Total == 0 {
			t.Fatal(category, v, err)
		}
		for _, e := range v.Events {
			if category == "screening" && e.Kind != "filtered" {
				t.Fatal("mixed history", e)
			}
			if category == "lifecycle" && e.Kind == "filtered" {
				t.Fatal("mixed lifecycle history", e)
			}
		}
	}
	if _, err := f.s.GetInvestigationCategory(f.ctx, 1, "unknown"); err == nil {
		t.Fatal("invalid category accepted")
	}
}

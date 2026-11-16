package admin

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
)

func TestInvestigationOutageAndControlEvidence(t *testing.T) {
	now := int64(10000)
	c := dispatchSplitCandidate{Version: 2, RunID: 4, Sequence: 23, Interval: 30, Timeout: 500, Reported: now, Error: "timeout"}
	samples := []DispatchHistorySample{}
	for i := int64(0); i < 24; i++ {
		samples = append(samples, DispatchHistorySample{Version: 2, RunID: 4, Sequence: 23 - i, ReportedAt: now - i*30, Error: "timeout", Success: i == 23})
	}
	first, ok := investigationTimeoutStart(samples, c, now, now-1000)
	if !ok || first != now-660 {
		t.Fatal(first, ok)
	}
	for _, name := range []string{"recovery", "gap", "session", "no_start", "short", "sequence"} {
		v := append([]DispatchHistorySample{}, samples...)
		switch name {
		case "recovery":
			v[4].Success = true
		case "gap":
			v[10].ReportedAt -= 200
		case "session":
			v[8].RunID = 3
		case "no_start":
			v = v[:23]
		case "short":
			v[15].Success = true
		case "sequence":
			v[8].Sequence--
		}
		if _, valid := investigationTimeoutStart(v, c, now, now-1000); valid {
			t.Fatal(name)
		}
	}
	controls := append([]DispatchHistorySample{}, samples...)
	controls = append(controls, DispatchHistorySample{Version: 2, RunID: 4, Sequence: -1, ReportedAt: now - 720, Success: true})
	for i := range controls {
		controls[i].Success = true
	}
	c.Success = true
	c.Error = ""
	if !investigationControlSpan(controls, c, first, now) {
		t.Fatal("healthy control rejected")
	}
	controls[5].Success = false
	if investigationControlSpan(controls, c, first, now) {
		t.Fatal("unstable control accepted")
	}
}

type investigationIntegration struct{ *splitIntegration }

func newInvestigationIntegration(t *testing.T) *investigationIntegration {
	f := newSplitIntegration(t)
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at) SELECT id,'invest-'||id||'@example.test','hash','00000000-0000-0000-0000-'||lpad(id::text,12,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM unnest(ARRAY[11,12,13,14,16,17]) id`)
	if err := f.s.ensureInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.s.SaveInvestigation(f.ctx, InvestigationSettings{Enabled: true, Revision: 1, EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	return &investigationIntegration{f}
}
func (f *investigationIntegration) groups() []InvestigationGroup {
	f.t.Helper()
	g, err := readInvestigationGroups(f.ctx, f.db, true)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}
func (f *investigationIntegration) group(host string) InvestigationGroup {
	for _, g := range f.groups() {
		if g.Host == host {
			return g
		}
	}
	f.t.Fatalf("missing group %s", host)
	return InvestigationGroup{}
}
func (f *investigationIntegration) execProcess(id int64) {
	f.t.Helper()
	// The database-wide advisory lock is also shared by isolated test schemas.
	// A busy automatic pass is deliberately skipped in production; retry only
	// that scheduling result here so the simulated pass actually executes.
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := f.s.processInvestigationAction(f.ctx, id, 0, false)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrInvestigationBusy) || time.Now().After(deadline) {
			f.t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Simulate receipt times in an isolated schema; production thresholds stay at
// ten minutes. Include one preceding success and every accepted sequence.
func (f *investigationIntegration) outage(g InvestigationGroup, pulled []int64) {
	f.t.Helper()
	f.execProcess(g.ID)
	c := f.timeout(g.Host)
	now := c.Reported
	epoch := now - 1000
	first := now - 630
	// The parent helper supplies sequences 1..22 as continuous timeouts.
	var minSeq int64
	if err := f.db.QueryRow(`SELECT min(sequence) FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND version=$2 AND run_id=$3`, c.ID, c.Version, c.RunID).Scan(&minSeq); err != nil {
		f.t.Fatal(err)
	}
	f.exec(`UPDATE v2_dispatch_history SET success=TRUE,payload=jsonb_set(jsonb_set(payload,'{success}','true'::jsonb),'{error}','""'::jsonb) WHERE target_id=$1 AND source='entry' AND sequence=$2`, c.ID, minSeq)
	first = now - (c.Sequence-minSeq-1)*30
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, epoch)
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2::bigint,ready_at=$2::bigint+1 WHERE id=$1`, g.ID, epoch)
	// Keep independent controls healthy for the whole same observation span.
	for _, other := range f.groups() {
		if other.Host == g.Host || other.ManualOnly {
			continue
		}
		task, ok := f.tasks(f.pid)[other.Host]
		if !ok {
			continue
		}
		yes := true
		lat := int64(5)
		results := []DNSProbeResult{}
		var existingSeq int64
		f.db.QueryRow(`SELECT COALESCE(max(sequence),0) FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, -task.TargetID, f.pid).Scan(&existingSeq)
		for n := int64(1); n <= 25; n++ {
			results = append(results, DNSProbeResult{ResultID: fmt.Sprintf("ctrl-%d", existingSeq+n), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &yes, LatencyMS: &lat, ResolvedIP: fmt.Sprintf("203.0.113.%d", other.ID+10)})
		}
		r, err := f.s.ReportDispatchProbeResults(f.ctx, f.pid, DNSProbeResultsRequest{Results: results})
		if err != nil || r.Accepted != 25 {
			f.t.Fatal(r, err)
		}
		var seq int64
		f.db.QueryRow(`SELECT sequence FROM v2_dispatch_monitor_state WHERE monitor_id=$1 AND probe_id=$2`, -task.TargetID, f.pid).Scan(&seq)
		f.exec(`UPDATE v2_dispatch_history SET created_at=$1-($3::bigint-sequence)*30,payload=jsonb_set(payload,'{reported_at}',to_jsonb($1::bigint-($3::bigint-sequence)*30)) WHERE source='entry' AND target_id=$2 AND version=$4 AND run_id=$5`, now, -task.TargetID, seq, task.TargetVersion, task.RunID)
		f.exec(`UPDATE v2_dispatch_monitor_state SET reported_at=$1 WHERE monitor_id=$2 AND probe_id=$3`, now, -task.TargetID, f.pid)
	}
	g = f.group(g.Host)
	for _, id := range pulled {
		if err := usersvc.NewDBService(f.s.cfg, f.db).RecordInvestigationDelivery(f.ctx, id, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, first-5); err != nil {
			f.t.Fatal(err)
		}
	}
}
func (f *investigationIntegration) successfulEvents() int {
	var count int
	f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind IN('filtered','bisected','no_pulls')`).Scan(&count)
	return count
}

func TestPostgresInvestigationFilterObservationMergeAndSingleton(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.201", "192.0.2.202", "192.0.2.203", "192.0.2.204")
	g := f.group("range.example")
	if len(g.UserIDs) != 8 {
		t.Fatal(g.UserIDs)
	}
	f.outage(g, []int64{11, 12, 13})
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		view, _ := f.s.GetInvestigation(f.ctx, 1)
		t.Fatalf("filter did not run: %#v", view.Groups)
	}
	var candidate, observation InvestigationGroup
	for _, v := range f.groups() {
		if v.ParentID == g.ID {
			if v.Kind == "recent" {
				candidate = v
			} else if v.Kind == "observation" {
				observation = v
			}
		}
	}
	if len(candidate.UserIDs) != 3 || len(observation.UserIDs) != 5 || candidate.Host == observation.Host {
		t.Fatal(candidate, observation)
	}
	if candidate.Name != "120分钟" || observation.Name != "观察" {
		t.Fatal(candidate.Name, observation.Name)
	}
	if f.process(dispatchSplitCandidate{ID: candidate.MonitorID, Host: candidate.Host}) {
		t.Fatal("old splitter touched investigation")
	}
	// Verify actual dispatch and preserve source-host-specific routing.
	u := usersvc.NewDBService(f.s.cfg, f.db)
	servers, err := u.Servers(f.ctx, 11, "")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(servers[0]["host"]) != candidate.Host {
		t.Fatal(servers)
	}
	// Repeated execution cannot consume another IP or event.
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("duplicate incident")
	}
	// Prepare observation as healthy and release the family's rolling cooldown.
	f.execProcess(observation.ID)
	f.exec(`UPDATE v2_dispatch_investigation_group SET ready_at=$1,epoch_at=$1 WHERE id=$2`, time.Now().Unix()-1200, observation.ID)
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
	f.outage(candidate, []int64{11})
	f.execProcess(candidate.ID)
	if f.successfulEvents() != 2 {
		t.Fatal(f.groups())
	}
	var single, merged InvestigationGroup
	for _, v := range f.groups() {
		if v.Kind == "confirmed" {
			single = v
		}
		if v.ID == observation.ID {
			merged = v
		}
	}
	if single.Name != "实锤内鬼" || !single.ManualOnly || single.Host != candidate.Host || !reflect.DeepEqual(single.UserIDs, []string{"11"}) || len(merged.UserIDs) != 7 || merged.Host != observation.Host {
		t.Fatal(single, merged)
	}
	if merged.Name != "观察" {
		t.Fatal(merged.Name)
	}
	snapshot := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")
	f.execProcess(single.ID)
	if !reflect.DeepEqual(snapshot, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
		t.Fatal("singleton changed")
	}
}

func TestPostgresInvestigationAllPulledBisectsActualPeople(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	ids := investigationGroupIDs(g)
	f.outage(g, ids)
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal(f.groups())
	}
	children := []InvestigationGroup{}
	for _, v := range f.groups() {
		if v.ParentID == g.ID {
			children = append(children, v)
		}
	}
	if len(children) != 2 || len(children[0].UserIDs) != 4 || len(children[1].UserIDs) != 4 || children[0].Host == children[1].Host {
		t.Fatal(children)
	}
}

func TestPostgresInvestigationRecentWindowAndRepeatedDelivery(t *testing.T) {
	for _, allPulled := range []bool{false, true} {
		t.Run(fmt.Sprint(allPulled), func(t *testing.T) {
			f := newInvestigationIntegration(t)
			f.pool("192.0.2.211", "192.0.2.212", "192.0.2.213")
			g := f.group("range.example")
			f.outage(g, nil)
			var first int64
			if err := f.db.QueryRow(`SELECT min((payload->>'reported_at')::bigint) FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND target_id=$1 AND NOT (payload->>'success')::boolean`, g.MonitorID).Scan(&first); err != nil {
				t.Fatal(err)
			}
			f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2::bigint,ready_at=$2::bigint+1 WHERE id=$1`, g.ID, first-9000)
			f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, first-9000)
			g = f.group(g.Host)
			u := usersvc.NewDBService(f.s.cfg, f.db)
			record := func(id, at int64) {
				t.Helper()
				if err := u.RecordInvestigationDelivery(f.ctx, id, []usersvc.InvestigationDelivery{{GroupID: g.ID, Generation: g.Generation, Host: g.Host}}, at); err != nil {
					t.Fatal(err)
				}
			}
			record(11, first-7201)
			record(12, first-8000)
			record(13, first-7200) // Inclusive window start.
			record(14, first-7199)
			record(15, first-8000)
			record(15, first-1) // A repeated pull must count, not only the first.
			record(15, first-1) // Retries in the same second are deduplicated.
			record(11, first+1) // Pulls after T cannot change the historical bucket.
			record(12, first)   // The first-failure second is excluded.
			record(16, first+1)
			if allPulled {
				for _, id := range []int64{16, 17, 42} {
					record(id, first-8000)
				}
			}
			f.execProcess(g.ID)
			if f.successfulEvents() != 1 {
				t.Fatal(f.groups())
			}
			want := map[string][]string{"recent": {"13", "14", "15"}, "candidate": {"11", "12"}, "observation": {"16", "17", "42"}}
			if allPulled {
				want["candidate"] = []string{"11", "12", "16", "17", "42"}
				delete(want, "observation")
			}
			hosts := map[string]bool{}
			for _, child := range f.groups() {
				if child.ParentID != g.ID {
					continue
				}
				if !reflect.DeepEqual(child.UserIDs, want[child.Kind]) || child.Name != investigationGroupName(child.Kind) || hosts[child.Host] || child.Host == g.Host {
					t.Fatal(child, want)
				}
				hosts[child.Host] = true
				delete(want, child.Kind)
			}
			if len(want) != 0 {
				t.Fatal(want)
			}
			var kind string
			if err := f.db.QueryRow(`SELECT kind FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind IN('filtered','bisected')`, g.ID).Scan(&kind); err != nil || kind != "filtered" {
				t.Fatal(kind, err)
			}
		})
	}
}

func TestPostgresInvestigationRecentUpgradePreservesAssignments(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.exec(`ALTER TABLE v2_dispatch_investigation_group DROP CONSTRAINT v2_dispatch_investigation_group_kind_check;
ALTER TABLE v2_dispatch_investigation_group ADD CONSTRAINT v2_dispatch_investigation_group_kind_check CHECK(kind IN('candidate','observation','confirmed'));
UPDATE v2_dispatch_investigation_settings SET recent_receipts_started_at=0`)
	f.exec(`UPDATE v2_dispatch_investigation_group SET generation=7,epoch_at=1,ready_at=1 WHERE id=$1`, g.ID)
	settings, err := readInvestigationSettings(f.ctx, f.db, false)
	if err != nil {
		t.Fatal(err)
	}
	apply := func() {
		for _, statement := range postgres.DispatchInvestigationSchema {
			f.exec(statement)
		}
	}
	apply()
	after := f.group(g.Host)
	if after.Generation != 8 || after.EpochAt <= 1 || after.ReadyAt != 0 || after.Host != g.Host || after.RootID != g.RootID || !reflect.DeepEqual(after.UserIDs, g.UserIDs) {
		t.Fatal(after)
	}
	current, err := readInvestigationSettings(f.ctx, f.db, false)
	if err != nil || !reflect.DeepEqual(settings, current) {
		t.Fatal(settings, current, err)
	}
	apply()
	if !reflect.DeepEqual(after, f.group(g.Host)) {
		t.Fatal("schema rerun restarted the observation round")
	}
	f.exec(`UPDATE v2_dispatch_investigation_group SET kind='recent' WHERE id=$1`, g.ID)
}

func TestPostgresInvestigationScopeBootstrapAndCompatibility(t *testing.T) {
	f := newSplitIntegration(t)
	settings := InvestigationSettings{Enabled: true, Scope: "multi_range", Revision: 1, EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}
	if err := f.s.SaveInvestigation(f.ctx, settings); err != nil {
		t.Fatal(err)
	}
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	groups, err := readInvestigationGroups(f.ctx, f.db, true)
	if err != nil || len(groups) != 1 || groups[0].Host != "base.example" {
		t.Fatal(groups, err)
	}
	// Single ranges and explicit IDs do not qualify merely because they own
	// several actual users. Multiple configured ranges do qualify.
	f.exec(`UPDATE v2_node_address_rule SET match_user_id_ranges='[]',match_user_ids='["15","42"]'`)
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	groups, err = readInvestigationGroups(f.ctx, f.db, true)
	if err != nil || len(groups) != 1 {
		t.Fatal("explicit IDs incorrectly qualified as multiple ranges", groups, err)
	}
	f.exec(`UPDATE v2_node_address_rule SET match_user_ids='[]',match_user_id_ranges='["10-20","40-100"]'`)
	if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	groups, err = readInvestigationGroups(f.ctx, f.db, true)
	if err != nil || len(groups) != 2 {
		t.Fatal(groups, err)
	}
	settings, err = readInvestigationSettings(f.ctx, f.db, false)
	if err != nil || settings.Scope != "multi_range" {
		t.Fatal(settings, err)
	}
	settings.Scope = "invalid"
	if err := f.s.SaveInvestigation(f.ctx, settings); err == nil {
		t.Fatal("invalid scope accepted")
	}
	settings.Scope = "" // Older clients must preserve the saved scope.
	if err := f.s.SaveInvestigation(f.ctx, settings); err != nil {
		t.Fatal(err)
	}
	settings, err = readInvestigationSettings(f.ctx, f.db, false)
	if err != nil || settings.Scope != "multi_range" {
		t.Fatal(settings, err)
	}
}

func TestPostgresInvestigationScopeSavedSwitchPreservesDispatch(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal(f.groups())
	}
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_check_target")
	entries, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"multi_range", "all"} {
		settings, err := readInvestigationSettings(f.ctx, f.db, false)
		if err != nil {
			t.Fatal(err)
		}
		previous := f.groups()
		settings.Scope = scope
		if err := f.s.SaveInvestigation(f.ctx, settings); err != nil {
			t.Fatal(err)
		}
		current, err := readInvestigationSettings(f.ctx, f.db, false)
		if err != nil || current.Scope != scope || current.Revision != settings.Revision+1 {
			t.Fatal(current, err)
		}
		if err := f.s.SaveInvestigation(f.ctx, settings); err == nil {
			t.Fatal("stale scope setting accepted")
		}
		groups := f.groups()
		for i, child := range groups {
			if child.Generation != previous[i].Generation+1 || child.ReadyAt != 0 {
				t.Fatal("scope change retained old observation evidence", child)
			}
			f.execProcess(child.ID)
		}
		if err := f.s.bootstrapInvestigation(f.ctx); err != nil {
			t.Fatal(err)
		}
		after, err := usersvc.DispatchEntriesFrom(f.ctx, f.db)
		if err != nil || !reflect.DeepEqual(entries, after) || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_check_target")) || f.successfulEvents() != 1 || len(f.groups()) != len(groups) {
			t.Fatal("scope switch changed dispatch or reused old failure", after, err)
		}
	}
}

func TestPostgresInvestigationScopeUpgradeDefaultsWithoutReset(t *testing.T) {
	f := newInvestigationIntegration(t)
	before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")
	f.exec(`ALTER TABLE v2_dispatch_investigation_settings DROP COLUMN scope`)
	for i := 0; i < 2; i++ {
		for _, statement := range postgres.DispatchInvestigationSchema {
			f.exec(statement)
		}
		settings, err := readInvestigationSettings(f.ctx, f.db, false)
		if err != nil || settings.Scope != "all" || !settings.Enabled || settings.EntryWindowMinutes != 20 || settings.GlobalMax != 3 {
			t.Fatal(settings, err)
		}
		if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
			t.Fatal("adding scope reset existing groups")
		}
	}
}

func TestPostgresInvestigationScopeStopsExistingAndFollowsRoot(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	f.exec(`UPDATE v2_dispatch_investigation_settings SET scope='multi_range'`)
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_check_target")
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor", "v2_dispatch_check_target")) {
		t.Fatal("out-of-scope existing group changed assignments")
	}
	f.exec(`UPDATE v2_node_address_rule SET match_user_id_ranges='["10-20","40-100"]'`)
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal(f.groups())
	}
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			ok, err := investigationGroupInScope(f.ctx, tx, "multi_range", child.RootID)
			if err != nil || !ok {
				t.Fatal("descendant lost original scope", child, err)
			}
		}
	}
}
func TestPostgresInvestigationNoPullAndInsufficientPool(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.outage(g, nil)
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 || f.group(g.Host).Reason == "" {
		t.Fatal("must wait for pool")
	}
	f.pool("192.0.2.221")
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal(f.groups())
	}
	for _, v := range f.groups() {
		if v.ID == g.ID {
			if v.NoPullCount != 1 || len(v.UserIDs) != 8 || v.Host == g.Host || v.Name == g.Name {
				t.Fatal(v)
			}
		}
	}
}
func TestPostgresInvestigationDefaultOffAndOriginalSingleton(t *testing.T) {
	f := newSplitIntegration(t)
	if err := f.s.ensureInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.s.investigationCycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	groups, err := readInvestigationGroups(f.ctx, f.db, true)
	if err != nil || len(groups) != 0 {
		t.Fatal(groups, err)
	}
	f.exec(`DELETE FROM v2_user WHERE id<>15`)
	if err = f.s.SaveInvestigation(f.ctx, InvestigationSettings{Enabled: true, Revision: 1, EntryWindowMinutes: 20, GlobalWindowMinutes: 60, GlobalMax: 3}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.bootstrapInvestigation(f.ctx); err != nil {
		t.Fatal(err)
	}
	groups, _ = readInvestigationGroups(f.ctx, f.db, true)
	if len(groups) != 1 || groups[0].ManualOnly || groups[0].Name == "实锤内鬼" {
		t.Fatal(groups)
	}
}

func TestPostgresInvestigationObservationAlsoBisectsAndSharesLimits(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.231", "192.0.2.232", "192.0.2.233", "192.0.2.234")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	f.execProcess(g.ID)
	var observation InvestigationGroup
	for _, v := range f.groups() {
		if v.ParentID == g.ID && v.Kind == "observation" {
			observation = v
		}
	}
	if observation.ID == 0 {
		t.Fatal(f.groups())
	}
	f.outage(observation, investigationGroupIDs(observation))
	f.execProcess(observation.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("descendant bypassed root cooldown")
	}
	f.exec(`UPDATE v2_dispatch_investigation_event SET created_at=created_at-1300 WHERE kind='filtered'`)
	f.exec(`UPDATE v2_dispatch_investigation_settings SET global_max=1`)
	f.execProcess(observation.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("global quota bypassed")
	}
	f.exec(`UPDATE v2_dispatch_investigation_settings SET global_max=3`)
	f.execProcess(observation.ID)
	if f.successfulEvents() != 2 {
		t.Fatal(f.groups())
	}
	children := []InvestigationGroup{}
	for _, v := range f.groups() {
		if v.ParentID == observation.ID {
			children = append(children, v)
		}
	}
	if len(children) != 2 || children[0].RootID != g.RootID || children[1].RootID != g.RootID || children[0].Host == children[1].Host || len(children[0].UserIDs)+len(children[1].UserIDs) != 5 {
		t.Fatal(children)
	}
	// Off preserves actual assignment but stops new actions. Restart also cannot
	// turn current descendants back into fresh original groups.
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")
	v, err := f.s.GetInvestigation(f.ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	v.Settings.Enabled = false
	if err = f.s.SaveInvestigation(f.ctx, v.Settings); err != nil {
		t.Fatal(err)
	}
	if err = f.s.investigationCycle(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_monitor")) {
		t.Fatal("off undid assignments")
	}
	for _, child := range children {
		if f.process(dispatchSplitCandidate{ID: child.MonitorID, Host: child.Host}) {
			t.Fatal("legacy automation touched managed group while off")
		}
	}
}

func TestPostgresInvestigationConflictingProbeAndUnstableControlBlock(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.241", "192.0.2.242")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12})
	// A successful control now is insufficient if it failed during the span.
	f.exec(`UPDATE v2_dispatch_history SET success=FALSE,payload=jsonb_set(payload,'{success}','false'::jsonb) WHERE source='entry' AND kind='sample' AND host='base.example' AND sequence=(SELECT max(sequence)-10 FROM v2_dispatch_history WHERE source='entry' AND kind='sample' AND host='base.example')`)
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 {
		t.Fatal("unstable peer accepted")
	}
	f.exec(`UPDATE v2_dispatch_history SET success=TRUE,payload=jsonb_set(payload,'{success}','true'::jsonb) WHERE source='entry' AND host='base.example'`)
	second := f.probe("second disagreement probe")
	// Changing a binding resets the round before considering any old timeout.
	f.exec(`INSERT INTO v2_dispatch_monitor_probe(monitor_id,probe_id) VALUES($1,$2)`, g.MonitorID, second)
	task := f.tasks(second)[g.Host]
	f.report(second, task, 1, 1, 0)
	f.execProcess(g.ID)
	if f.successfulEvents() != 0 {
		t.Fatal("conflicting probe executed")
	}
	g = f.group(g.Host)
	if g.ReadyAt != 0 {
		t.Fatal("binding change did not reset evidence")
	}
}

func TestPostgresInvestigationManualEditRevisionAndOriginalSingleStop(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	edit := InvestigationEdit{ID: g.ID, Revision: g.Revision, Name: "人工候选", Host: "192.0.2.250", ManualOnly: true}
	if err := f.s.EditInvestigation(f.ctx, edit); err != nil {
		t.Fatal(err)
	}
	if err := f.s.EditInvestigation(f.ctx, edit); err == nil {
		t.Fatal("stale edit accepted")
	}
	updated := f.group(edit.Host)
	if !updated.ManualOnly || updated.Name != edit.Name {
		t.Fatal(updated)
	}
	before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_monitor")
	f.execProcess(updated.ID)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_monitor")) {
		t.Fatal("manual group automated")
	}
	servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, 11, "")
	if err != nil || fmt.Sprint(servers[0]["host"]) != edit.Host {
		t.Fatal(servers, err)
	}
}

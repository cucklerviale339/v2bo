package postgres

import (
	"encoding/json"
	"reflect"
	"testing"
)

func riskEvent(id, root, group int64, kind, payload string) DispatchRiskEvent {
	return DispatchRiskEvent{ID: id, RootID: root, GroupID: group, Kind: kind, CreatedAt: id * 100, Payload: json.RawMessage(payload)}
}

func blockedRiskUsers(cases []*DispatchRiskCase, members []*DispatchRiskMember) map[int64]bool {
	open := map[int64]bool{}
	for _, c := range cases {
		open[c.EventID] = c.ResolvedEventID == 0
	}
	users := map[int64]bool{}
	for _, m := range members {
		if open[m.EventID] && m.ClearedEventID == 0 {
			users[m.UserID] = true
		}
	}
	return users
}

func TestDispatchBranchRiskRecentAndOlderAreBothCandidates(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2,3,4],"recent_ids":[1,2],"older_ids":[3,4],"unpulled_ids":[5,6],"partitions":[{"group_id":2,"user_ids":[1,2]},{"group_id":3,"user_ids":[3,4]},{"group_id":4,"user_ids":[5,6]}]}`),
		riskEvent(2, 1, 2, "filtered", `{"pulled_ids":[1],"unpulled_ids":[2],"partitions":[{"group_id":5,"user_ids":[1]},{"group_id":4,"user_ids":[2]}]}`),
	}
	cases, members, err := ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{1: true, 3: true, 4: true}) {
		t.Fatal(cases, members, err)
	}
	// The observation branch can have a separate incident later. Releasing
	// user 2 from an ancestor must not immunize that user against new evidence.
	events = append(events, riskEvent(3, 1, 4, "filtered", `{"pulled_ids":[2,5],"unpulled_ids":[6],"partitions":[{"group_id":6,"user_ids":[2]},{"group_id":7,"user_ids":[5]}]}`))
	cases, members, err = ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{1: true, 2: true, 3: true, 4: true, 5: true}) {
		t.Fatal(cases, members, err)
	}
}

func TestDispatchBranchRiskFollowsMovesAndDoesNotClearUnrelatedCase(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2],"partitions":[{"group_id":2,"user_ids":[1,2]}]}`),
		riskEvent(2, 99, 99, "filtered", `{"pulled_ids":[2],"partitions":[{"group_id":100,"user_ids":[2]}]}`),
		riskEvent(3, 1, 2, "stable_promoted", `{"user_ids":[1,2],"target_group_id":10}`),
		riskEvent(4, 1, 10, "members_moved", `{"user_ids":[1,2],"target_group_id":11}`),
		riskEvent(5, 1, 11, "stage_corrected", `{"user_ids":[1,2],"target_group_id":12}`),
		riskEvent(6, 1, 12, "filtered", `{"pulled_ids":[1],"unpulled_ids":[2],"partitions":[{"group_id":13,"user_ids":[1]},{"group_id":14,"user_ids":[2]}]}`),
	}
	cases, members, err := ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{1: true, 2: true}) {
		t.Fatal(cases, members, err)
	}
	for _, m := range members {
		if m.EventID == 1 && m.UserID == 2 && m.ClearedEventID != 6 {
			t.Fatal("ancestor was not narrowed", m)
		}
	}
	events = append(events, riskEvent(7, 1, 13, "filtered", `{"pulled_ids":[1],"partitions":[{"group_id":15,"user_ids":[1]}],"confirmation":{"version":1,"user_id":1,"related_roots":[1,99]}}`))
	cases, members, err = ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{2: true}) {
		t.Fatal("proof cleared a different branch", cases, members, err)
	}
}

func TestDispatchBranchRiskNoPullAndUnscreenedEdit(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "bisected", `{"pulled_ids":[1,2],"partitions":[{"group_id":2,"user_ids":[1]},{"group_id":3,"user_ids":[2]}]}`),
		riskEvent(2, 1, 2, "no_pulls", `{"pulled_ids":[],"unpulled_ids":[1],"partitions":[{"group_id":2,"user_ids":[1]}]}`),
		riskEvent(3, 1, 3, "edited", `{"removed_ids":[2]}`),
		riskEvent(4, 1, 22, "filtered", `{"pulled_ids":[3],"unpulled_ids":[2]}`),
	}
	cases, members, err := ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{2: true, 3: true}) {
		t.Fatal("unknown edit or unrelated result erased evidence", cases, members, err)
	}
}

func TestDispatchBranchRiskHistoricalMergeTracksOnlyItsConcreteSources(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2,3],"partitions":[{"group_id":2,"user_ids":[1,2]},{"group_id":3,"user_ids":[3]}]}`),
		riskEvent(2, 99, 99, "filtered", `{"pulled_ids":[2],"partitions":[{"group_id":100,"user_ids":[2]}]}`),
		riskEvent(3, 10, 10, "started", `{"user_ids":[1,2],"source_group_ids":[2]}`),
		riskEvent(4, 20, 20, "started", `{"user_ids":[1,2,3],"merged_group_ids":[10,3]}`),
		riskEvent(5, 20, 20, "filtered", `{"pulled_ids":[1,3],"older_ids":[3],"unpulled_ids":[2],"partitions":[{"group_id":21,"user_ids":[1]},{"group_id":22,"user_ids":[3]}]}`),
	}
	cases, members, err := ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{1: true, 2: true, 3: true}) {
		t.Fatal(cases, members, err)
	}
	for _, m := range members {
		if m.EventID == 1 && m.UserID == 2 && m.ClearedEventID != 5 {
			t.Fatal("historical merged branch did not narrow", m)
		}
	}
	// A proof in the new root may release its inherited source cases. A case
	// in another root which was never merged remains open for that same user.
	events = append(events, riskEvent(6, 20, 21, "filtered", `{"pulled_ids":[1],"confirmation":{"version":1,"user_id":1,"related_roots":[20]}}`))
	cases, members, err = ProjectDispatchRisk(events)
	if err != nil || !reflect.DeepEqual(blockedRiskUsers(cases, members), map[int64]bool{2: true}) {
		t.Fatal("merged proof lost its lineage or released unrelated risk", cases, members, err)
	}
}

func TestDispatchBranchRiskThreeRootsPauseReleaseAndIndependentFaults(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2,3,4],"unpulled_ids":[5,6],"partitions":[{"group_id":11,"user_ids":[1,2]},{"group_id":12,"user_ids":[3,4]},{"group_id":13,"user_ids":[5,6]}]}`),
		riskEvent(2, 2, 2, "filtered", `{"pulled_ids":[20,21],"unpulled_ids":[22],"partitions":[{"group_id":21,"user_ids":[20]},{"group_id":22,"user_ids":[21]},{"group_id":23,"user_ids":[22]}]}`),
		riskEvent(3, 3, 3, "filtered", `{"pulled_ids":[30,31],"unpulled_ids":[32],"partitions":[{"group_id":31,"user_ids":[30]},{"group_id":32,"user_ids":[31]},{"group_id":33,"user_ids":[32]}]}`),
	}
	project := func() map[int64]DispatchRiskUserState {
		t.Helper()
		c, m, e := ProjectDispatchRisk(events)
		if e != nil {
			t.Fatal(e)
		}
		return DispatchRiskUsers(c, m)
	}
	st := project()
	for _, id := range []int64{1, 2, 3, 4, 20, 21, 30, 31} {
		if !st[id].Blocked {
			t.Fatal("initial pulled branch clock not paused", id)
		}
	}
	events = append(events, riskEvent(4, 1, 11, "filtered", `{"pulled_ids":[1],"unpulled_ids":[2],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[12,13]},"partitions":[{"group_id":111,"user_ids":[1]},{"group_id":113,"user_ids":[2]}]}`))
	st = project()
	for _, id := range []int64{2, 3, 4} {
		if st[id].Blocked || st[id].ReleasedAt != 400 {
			t.Fatal("sibling must start at release, never parent birth", id, st[id])
		}
	}
	for _, id := range []int64{1, 20, 21, 30, 31} {
		if !st[id].Blocked {
			t.Fatal("another branch was cleared", id)
		}
	}
	// B later has faults in two separate branches. Neither cancels the other.
	events = append(events, riskEvent(5, 2, 21, "filtered", `{"pulled_ids":[20],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[22]},"partitions":[{"group_id":211,"user_ids":[20]}]}`))
	events = append(events, riskEvent(6, 2, 22, "filtered", `{"pulled_ids":[21],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[211]},"partitions":[{"group_id":221,"user_ids":[21]}]}`))
	st = project()
	if !st[20].Blocked || !st[21].Blocked {
		t.Fatal("independent child cases cancelled each other", st)
	}
	// C's non-recipient branch later faults: track its ancestry but create
	// candidate evidence only for users who actually pulled that new entrance.
	events = append(events, riskEvent(7, 3, 33, "filtered", `{"pulled_ids":[32],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[31,32]},"partitions":[{"group_id":331,"user_ids":[32]}]}`))
	st = project()
	if st[30].Blocked || st[31].Blocked || st[30].ReleasedAt != 700 || !st[32].Blocked {
		t.Fatal("observation fault ancestry", st)
	}
}

func TestDispatchBranchRiskNoSiblingReleaseWithoutConfirmedIndependentHealth(t *testing.T) {
	base := riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2,3],"partitions":[{"group_id":2,"user_ids":[1]},{"group_id":3,"user_ids":[2]},{"group_id":4,"user_ids":[3]}]}`)
	for _, raw := range []string{
		`{"pulled_ids":[1],"risk_narrowing":{"confirmed":false,"healthy_group_ids":[3,4]}}`,
		`{"pulled_ids":[1],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[]}}`,
		`{"pulled_ids":[],"unpulled_ids":[1],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[3,4]}}`,
		`{"pulled_ids":[1],"evidence":{"mode":"manual","first_failure_at":1,"controls":{"1":["healthy"]}}}`,
	} {
		c, m, e := ProjectDispatchRisk([]DispatchRiskEvent{base, riskEvent(2, 1, 2, "filtered", raw)})
		if e != nil {
			t.Fatal(e)
		}
		st := DispatchRiskUsers(c, m)
		if !st[2].Blocked || !st[3].Blocked {
			t.Fatal("unverified sibling release", raw, st)
		}
	}
}

func TestDispatchBranchRiskPoolWaitConfirmationIsIdempotent(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2],"partitions":[{"group_id":2,"user_ids":[1]},{"group_id":3,"user_ids":[2]}]}`),
		riskEvent(2, 1, 2, "branch_fault", `{"pulled_ids":[1],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[3]}}`),
		riskEvent(3, 1, 2, "filtered", `{"pulled_ids":[1],"partitions":[{"group_id":4,"user_ids":[1]}],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[3]}}`),
	}
	c, m, e := ProjectDispatchRisk(events)
	if e != nil {
		t.Fatal(e)
	}
	st := DispatchRiskUsers(c, m)
	if st[2].Blocked || st[2].ReleasedAt != 200 || !st[1].Blocked {
		t.Fatal("pool refill reset sibling clock or lost candidate", st)
	}
}

func TestDispatchBranchRiskLegacyControlsDefineSiblingClockBoundary(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"before":{"host":"old"},"pulled_ids":[1,2,3],"partitions":[{"group_id":2,"host":"failed","user_ids":[1]},{"group_id":3,"host":"healthy","user_ids":[2]},{"group_id":4,"host":"unknown","user_ids":[3]}]}`),
		riskEvent(2, 1, 2, "filtered", `{"before":{"host":"failed"},"pulled_ids":[1],"evidence":{"mode":"automatic","first_failure_at":150,"probe_ids":[9],"controls":{"9":["healthy"]}},"partitions":[{"group_id":5,"host":"new","user_ids":[1]}]}`),
	}
	c, m, e := ProjectDispatchRisk(events)
	if e != nil {
		t.Fatal(e)
	}
	st := DispatchRiskUsers(c, m)
	if st[2].Blocked || st[2].ReleasedAt != 200 || !st[1].Blocked || !st[3].Blocked {
		t.Fatal("legacy health was invented or clock backdated", st)
	}
}

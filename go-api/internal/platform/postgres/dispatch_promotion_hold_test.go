package postgres

import "testing"

func TestDispatchBranchRiskPromotionHoldNeedsOwnConfirmedPartition(t *testing.T) {
	base := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "filtered", `{"pulled_ids":[1,2,3,4,5],"partitions":[{"group_id":2,"user_ids":[1,2,3,4]},{"group_id":3,"user_ids":[5]}]}`),
		riskEvent(2, 1, 2, "stage_corrected", `{"user_ids":[1,2,3,4],"target_group_id":10,"promotion_hold":true}`),
	}
	for name, event := range map[string]DispatchRiskEvent{
		"healthy sibling fault": riskEvent(3, 1, 3, "filtered", `{"pulled_ids":[5],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[10]},"partitions":[{"group_id":30,"user_ids":[5]}]}`),
		"pool wait":             riskEvent(3, 1, 10, "branch_fault", `{"pulled_ids":[1,2],"unpulled_ids":[3,4],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[]}}`),
		"manual partition":      riskEvent(3, 1, 10, "filtered", `{"pulled_ids":[1,2],"unpulled_ids":[3,4],"risk_narrowing":{"confirmed":false,"healthy_group_ids":[]},"partitions":[{"group_id":11,"user_ids":[1,2]},{"group_id":12,"user_ids":[3,4]}]}`),
		"no pulls":              riskEvent(3, 1, 10, "no_pulls", `{"unpulled_ids":[1,2,3,4],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[]},"partitions":[{"group_id":10,"user_ids":[1,2,3,4]}]}`),
		"whole recovery":        riskEvent(3, 1, 10, "recovered", `{"unpulled_ids":[1,2,3,4],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[]},"partitions":[{"group_id":11,"user_ids":[1,2,3,4]}]}`),
		"renamed":               riskEvent(3, 1, 10, "edited", `{"name":"ordinary"}`),
		"empty child":           riskEvent(3, 1, 10, "filtered", `{"pulled_ids":[1,2,3,4],"risk_narrowing":{"confirmed":true},"partitions":[{"group_id":11,"user_ids":[1,2,3,4]},{"group_id":12,"user_ids":[]}]}`),
		"same child twice":      riskEvent(3, 1, 10, "filtered", `{"pulled_ids":[1,2],"unpulled_ids":[3,4],"risk_narrowing":{"confirmed":true},"partitions":[{"group_id":11,"user_ids":[1,2]},{"group_id":11,"user_ids":[3,4]}]}`),
	} {
		t.Run(name, func(t *testing.T) {
			c, m, err := ProjectDispatchRisk(append(append([]DispatchRiskEvent{}, base...), event))
			if err != nil {
				t.Fatal(err)
			}
			st := DispatchRiskUsers(c, m)
			for _, uid := range []int64{1, 2, 3, 4} {
				if !st[uid].Blocked {
					t.Fatal("correction hold bypassed", uid, st[uid])
				}
			}
		})
	}
	// The same successfully committed event clears the dedicated hold and
	// applies normal evidence: actual recipients pause, non-recipients restart.
	confirmed := riskEvent(3, 1, 10, "filtered", `{"pulled_ids":[1,2],"unpulled_ids":[3,4],"risk_narrowing":{"confirmed":true,"healthy_group_ids":[]},"partitions":[{"group_id":11,"user_ids":[1,2]},{"group_id":12,"user_ids":[3,4]}]}`)
	c, m, err := ProjectDispatchRisk(append(base, confirmed))
	if err != nil {
		t.Fatal(err)
	}
	st := DispatchRiskUsers(c, m)
	for _, uid := range []int64{1, 2} {
		if !st[uid].Blocked {
			t.Fatal("recipient candidate released", uid)
		}
	}
	for _, uid := range []int64{3, 4} {
		if st[uid].Blocked || st[uid].ReleasedAt != 300 {
			t.Fatal("non-recipient did not start at committed confirmation", uid, st[uid])
		}
	}
}

func TestDispatchBranchRiskPromotionHoldFollowsManualMovesAndReplays(t *testing.T) {
	events := []DispatchRiskEvent{
		riskEvent(1, 1, 1, "stage_corrected", `{"user_ids":[1,2],"target_group_id":10,"promotion_hold":true}`),
		riskEvent(2, 1, 10, "members_moved", `{"user_ids":[1,2],"target_group_id":20}`),
		riskEvent(3, 1, 20, "filtered", `{"pulled_ids":[1],"unpulled_ids":[2],"risk_narrowing":{"confirmed":false},"partitions":[{"group_id":21,"user_ids":[1]},{"group_id":22,"user_ids":[2]}]}`),
	}
	for i := 0; i < 2; i++ {
		c, m, err := ProjectDispatchRisk(events)
		if err != nil {
			t.Fatal(err)
		}
		st := DispatchRiskUsers(c, m)
		if !st[1].Blocked || !st[2].Blocked {
			t.Fatal("manual move or restart erased hold", st)
		}
		for _, member := range m {
			if member.EventID == 1 && (member.UserID == 1 && member.GroupID != 21 || member.UserID == 2 && member.GroupID != 22) {
				t.Fatal("hold lost lineage", member)
			}
		}
	}
}

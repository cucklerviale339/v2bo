package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
)

// Replay actual dispatch branches. A fault pauses both recent and older
// recipients. A later confirmed fault releases healthy sibling branches from
// that ancestor case, with a new personal clock boundary at release time.
type DispatchRiskEvent struct {
	ID        int64           `json:"id"`
	RootID    int64           `json:"root_id"`
	GroupID   int64           `json:"group_id"`
	Kind      string          `json:"kind"`
	CreatedAt int64           `json:"created_at"`
	Payload   json.RawMessage `json:"payload"`
}

type DispatchRiskCase struct {
	EventID         int64 `json:"event_id"`
	CreatedAt       int64 `json:"created_at"`
	ResolvedEventID int64 `json:"resolved_event_id"`
	ResolvedAt      int64 `json:"resolved_at"`
	root            int64
	members         map[int64]*DispatchRiskMember
	watch           map[int64]int64
	promotionHold   bool
}

type DispatchRiskMember struct {
	EventID        int64 `json:"event_id"`
	UserID         int64 `json:"user_id"`
	GroupID        int64 `json:"group_id"`
	ClearedEventID int64 `json:"cleared_event_id"`
	ClearedAt      int64 `json:"cleared_at"`
}

type dispatchRiskPayload struct {
	Pulled        []int64         `json:"pulled_ids"`
	Unpulled      []int64         `json:"unpulled_ids"`
	Users         []int64         `json:"user_ids"`
	Host          string          `json:"host"`
	Target        int64           `json:"target_group_id"`
	Sources       []int64         `json:"source_group_ids"`
	Merged        []int64         `json:"merged_group_ids"`
	PromotionHold bool            `json:"promotion_hold"`
	Before        json.RawMessage `json:"before"`
	Parts         []struct {
		Group int64   `json:"group_id"`
		Users []int64 `json:"user_ids"`
		Host  string  `json:"host"`
	} `json:"partitions"`
	Evidence struct {
		Mode       string             `json:"mode"`
		First      int64              `json:"first_failure_at"`
		Incomplete bool               `json:"receipts_incomplete"`
		Controls   map[int64][]string `json:"controls"`
		Probes     []int64            `json:"probe_ids"`
	} `json:"evidence"`
	Narrowing    *DispatchRiskNarrowing `json:"risk_narrowing"`
	Confirmation *struct {
		Version int     `json:"version"`
		User    int64   `json:"user_id"`
		Roots   []int64 `json:"related_roots"`
	} `json:"confirmation"`
}

// Persist a decision while its actual dispatch and probe evidence are still
// available. Manual execution alone never means that a fault was confirmed.
type DispatchRiskNarrowing struct {
	Confirmed     bool    `json:"confirmed"`
	HealthyGroups []int64 `json:"healthy_group_ids"`
}

func ProjectDispatchRisk(events []DispatchRiskEvent) ([]*DispatchRiskCase, []*DispatchRiskMember, error) {
	ordered := append([]DispatchRiskEvent{}, events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	cases, members := []*DispatchRiskCase{}, []*DispatchRiskMember{}
	hosts := map[int64]string{}
	clear := func(c *DispatchRiskCase, uid int64, e DispatchRiskEvent) {
		if m := c.members[uid]; m != nil && m.ClearedEventID == 0 && c.ResolvedEventID == 0 {
			m.ClearedEventID, m.ClearedAt = e.ID, e.CreatedAt
		}
	}
	for _, e := range ordered {
		p, err := decodeDispatchRiskPayload(e.Kind, e.Payload)
		if err != nil {
			return nil, nil, &DispatchRiskHistoryIssue{EventID: e.ID, RootID: e.RootID, GroupID: e.GroupID, Kind: e.Kind, cause: err}
		}
		if host := dispatchAuditHost(p.Before); host != "" {
			hosts[e.GroupID] = host
		}
		if p.Host != "" {
			target := e.GroupID
			if p.Target > 0 {
				target = p.Target
			}
			hosts[target] = p.Host
		}
		screen := e.Kind == "filtered" || e.Kind == "bisected" || e.Kind == "whitelist_bisected" || e.Kind == "no_pulls" || e.Kind == "branch_fault"
		if !screen {
			sources, target := []int64{e.GroupID}, p.Target
			if e.Kind == "members_admitted" {
				sources, target = []int64{e.RootID}, e.GroupID
			}
			if e.Kind == "started" {
				sources = append(append([]int64{}, p.Sources...), p.Merged...)
				target = e.GroupID
			}
			if target > 0 && (e.Kind == "stable_promoted" || e.Kind == "whitelist_promoted" || e.Kind == "members_moved" || e.Kind == "stage_corrected" || e.Kind == "members_admitted" || e.Kind == "started") {
				for _, c := range cases {
					for _, uid := range p.Users {
						for _, source := range sources {
							if c.watch[uid] == source {
								c.watch[uid] = target
								if m := c.members[uid]; m != nil {
									m.GroupID = target
								}
								break
							}
						}
					}
				}
			}
			// Whole-group recovery normally retains its ID. A merge into another
			// observation group still transfers lineage, without clearing evidence.
			if e.Kind == "recovered" || e.Kind == "observation_repaired" || e.Kind == "whitelist_failed_over" {
				for _, part := range p.Parts {
					for _, c := range cases {
						for _, uid := range part.Users {
							if part.Group > 0 && c.watch[uid] == e.GroupID {
								c.watch[uid] = part.Group
								if m := c.members[uid]; m != nil {
									m.GroupID = part.Group
								}
							}
						}
					}
				}
			}
			// Correction rosters must remain isolated from timed promotion until
			// their own later fault is confirmed AND its partition commits.
			// Replay this fact from the audit so restarts/edits cannot erase it.
			if e.Kind == "stage_corrected" && p.PromotionHold && p.Target > 0 {
				c := &DispatchRiskCase{EventID: e.ID, CreatedAt: e.CreatedAt, root: e.RootID, members: map[int64]*DispatchRiskMember{}, watch: map[int64]int64{}, promotionHold: true}
				cases = append(cases, c)
				for _, uid := range p.Users {
					if uid <= 0 || c.members[uid] != nil {
						continue
					}
					m := &DispatchRiskMember{EventID: e.ID, UserID: uid, GroupID: p.Target}
					c.members[uid], c.watch[uid] = m, p.Target
					members = append(members, m)
				}
			}
		} else {
			yes, no, dest := map[int64]bool{}, map[int64]bool{}, map[int64]int64{}
			for _, uid := range p.Pulled {
				if uid > 0 {
					yes[uid] = true
				}
			}
			for _, uid := range p.Unpulled {
				if uid > 0 && !yes[uid] {
					no[uid] = true
				}
			}
			for _, part := range p.Parts {
				for _, uid := range part.Users {
					if part.Group > 0 {
						dest[uid] = part.Group
					}
				}
			}
			healthy := map[int64]bool{}
			confirmed := false
			if p.Narrowing != nil {
				confirmed = p.Narrowing.Confirmed
				for _, group := range p.Narrowing.HealthyGroups {
					healthy[group] = true
				}
			} else if p.Evidence.Mode != "manual" && p.Evidence.First > 0 && !p.Evidence.Incomplete && len(p.Evidence.Controls) > 0 {
				// Old audits retain successful independent controls over the fault
				// verification window. Do not invent health for absent or stale siblings.
				confirmed = true
				for group, host := range hosts {
					if host == "" || host == hosts[e.GroupID] {
						continue
					}
					ok := true
					for _, list := range p.Evidence.Controls {
						found := false
						for _, h := range list {
							found = found || h == host
						}
						ok = ok && found
					}
					for _, probe := range p.Evidence.Probes {
						if len(p.Evidence.Controls[probe]) == 0 {
							ok = false
						}
					}
					healthy[group] = ok
				}
			}
			// A no-recipient round cannot attribute the failure to a candidate branch.
			// It clears explicit non-recipients only, without releasing other siblings.
			confirmed = confirmed && len(yes) > 0 && !p.Evidence.Incomplete
			touched := map[int64]bool{}
			for _, c := range cases {
				if c.ResolvedEventID != 0 {
					continue
				}
				onBranch := false
				for uid, group := range c.watch {
					if group == e.GroupID && (yes[uid] || no[uid]) {
						onBranch = true
						break
					}
				}
				if !onBranch {
					continue
				}
				if c.promotionHold {
					childGroups := map[int64]bool{}
					for uid, group := range dest {
						if yes[uid] || no[uid] {
							childGroups[group] = true
						}
					}
					partitioned := confirmed && len(childGroups) > 1 && (e.Kind == "filtered" || e.Kind == "bisected" || e.Kind == "whitelist_bisected")
					for uid, group := range c.watch {
						if group != e.GroupID {
							continue
						}
						if to := dest[uid]; to > 0 {
							if partitioned && (yes[uid] || no[uid]) {
								clear(c, uid, e)
							}
							c.watch[uid] = to
							c.members[uid].GroupID = to
						}
					}
					continue
				}
				if confirmed {
					for uid, group := range c.watch {
						if group != e.GroupID && healthy[group] {
							clear(c, uid, e)
							delete(c.watch, uid)
						}
					}
				}
				for uid, group := range c.watch {
					if group != e.GroupID {
						continue
					}
					if no[uid] {
						clear(c, uid, e)
					}
					if yes[uid] && p.Confirmation != nil && uid == p.Confirmation.User {
						touched[c.EventID] = true
					}
					if to := dest[uid]; to > 0 {
						c.watch[uid] = to
						if m := c.members[uid]; m != nil {
							m.GroupID = to
						}
					}
				}
			}
			if e.Kind != "no_pulls" && len(yes) > 0 {
				c := &DispatchRiskCase{EventID: e.ID, CreatedAt: e.CreatedAt, root: e.RootID, members: map[int64]*DispatchRiskMember{}, watch: map[int64]int64{}}
				cases = append(cases, c)
				// Track non-recipients too: a later fault in their observation branch
				// can narrow the ancestor case, but never makes them past candidates.
				for _, uid := range append(append([]int64{}, p.Pulled...), p.Unpulled...) {
					if uid <= 0 {
						continue
					}
					group := dest[uid]
					if group == 0 {
						group = e.GroupID
					}
					c.watch[uid] = group
					if yes[uid] && c.members[uid] == nil {
						m := &DispatchRiskMember{EventID: e.ID, UserID: uid, GroupID: group}
						c.members[uid] = m
						members = append(members, m)
					}
				}
				touched[e.ID] = true
			}
			if p.Confirmation != nil && p.Confirmation.Version == 1 && yes[p.Confirmation.User] {
				roots := map[int64]bool{}
				for _, root := range p.Confirmation.Roots {
					roots[root] = true
				}
				for _, c := range cases {
					if c.ResolvedEventID == 0 && touched[c.EventID] && (roots[c.root] || roots[e.RootID]) {
						c.ResolvedEventID, c.ResolvedAt = e.ID, e.CreatedAt
						c.watch = map[int64]int64{}
					}
				}
			}
		}
		for _, part := range p.Parts {
			if part.Group > 0 && part.Host != "" {
				hosts[part.Group] = part.Host
			}
		}
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].EventID != members[j].EventID {
			return members[i].EventID < members[j].EventID
		}
		return members[i].UserID < members[j].UserID
	})
	return cases, members, nil
}

// The same user state is used by eligibility, corrections and read-only audits.
type DispatchRiskUserState struct {
	Blocked    bool  `json:"blocked"`
	ReleasedAt int64 `json:"released_at"`
}

func DispatchRiskUsers(cases []*DispatchRiskCase, members []*DispatchRiskMember) map[int64]DispatchRiskUserState {
	byID := map[int64]*DispatchRiskCase{}
	for _, c := range cases {
		byID[c.EventID] = c
	}
	out := map[int64]DispatchRiskUserState{}
	for _, m := range members {
		c := byID[m.EventID]
		state := out[m.UserID]
		state.Blocked = state.Blocked || (c.ResolvedEventID == 0 && m.ClearedEventID == 0)
		at := c.ResolvedAt
		if m.ClearedEventID > 0 {
			at = m.ClearedAt
		}
		state.ReleasedAt = max(state.ReleasedAt, at)
		out[m.UserID] = state
	}
	return out
}

// Called while holding the same transaction advisory lock as dispatch edits.
// Historical backfill and live writes deliberately share this one reducer.
func RefreshDispatchRisk(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, `SELECT id,root_id,group_id,kind,created_at,COALESCE(risk_payload,payload) FROM v2_dispatch_investigation_event ORDER BY id`)
	if err != nil {
		return err
	}
	events := []DispatchRiskEvent{}
	for rows.Next() {
		var e DispatchRiskEvent
		if err = rows.Scan(&e.ID, &e.RootID, &e.GroupID, &e.Kind, &e.CreatedAt, &e.Payload); err != nil {
			rows.Close()
			return err
		}
		events = append(events, e)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	cases, members, err := ProjectDispatchRisk(events)
	if err != nil {
		issue, ok := err.(*DispatchRiskHistoryIssue)
		if !ok {
			return err
		}
		// Keep the complete prior projection. A missing transition could
		// invalidate later clearances, even in another branch.
		return saveDispatchRiskHistoryIssue(ctx, tx, issue)
	}
	if err = saveDispatchRiskHistoryIssue(ctx, tx, nil); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	rawCases, _ := json.Marshal(cases)
	rawMembers, _ := json.Marshal(members)
	if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_risk_case(event_id,created_at,resolved_event_id,resolved_at) SELECT event_id,created_at,resolved_event_id,resolved_at FROM jsonb_to_recordset($1::jsonb) x(event_id bigint,created_at bigint,resolved_event_id bigint,resolved_at bigint) ON CONFLICT(event_id) DO UPDATE SET resolved_event_id=EXCLUDED.resolved_event_id,resolved_at=EXCLUDED.resolved_at WHERE (v2_dispatch_risk_case.resolved_event_id,v2_dispatch_risk_case.resolved_at) IS DISTINCT FROM (EXCLUDED.resolved_event_id,EXCLUDED.resolved_at)`, string(rawCases)); err != nil {
		return err
	}
	// Remove only obsolete projection rows, never original screening history.
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_risk_member m WHERE NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) x(event_id bigint,user_id bigint) WHERE x.event_id=m.event_id AND x.user_id=m.user_id)`, string(rawMembers)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_risk_case c WHERE NOT EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) x(event_id bigint) WHERE x.event_id=c.event_id)`, string(rawCases)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO v2_dispatch_risk_member(event_id,user_id,group_id,cleared_event_id,cleared_at) SELECT event_id,user_id,group_id,cleared_event_id,cleared_at FROM jsonb_to_recordset($1::jsonb) x(event_id bigint,user_id bigint,group_id bigint,cleared_event_id bigint,cleared_at bigint) ON CONFLICT(event_id,user_id) DO UPDATE SET group_id=EXCLUDED.group_id,cleared_event_id=EXCLUDED.cleared_event_id,cleared_at=EXCLUDED.cleared_at WHERE (v2_dispatch_risk_member.group_id,v2_dispatch_risk_member.cleared_event_id,v2_dispatch_risk_member.cleared_at) IS DISTINCT FROM (EXCLUDED.group_id,EXCLUDED.cleared_event_id,EXCLUDED.cleared_at)`, string(rawMembers)); err != nil {
		return err
	}
	return nil
}

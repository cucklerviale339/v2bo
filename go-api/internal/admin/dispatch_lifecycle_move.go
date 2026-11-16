package admin

import (
	"context"
	"database/sql"
	"reflect"
	"sort"

	usersvc "forest/go-api/internal/user"
)

// One endpoint may represent several independent business assignments for the
// same person. Stage moves transfer only the source group's origin/user rows;
// another business may legitimately continue delivering the old endpoint.
type investigationBusinessMove struct {
	source      int64
	users       map[int64]bool
	base        []usersvc.DispatchEntry
	assignments []usersvc.InvestigationAssignment
}

func planInvestigationBusinessMove(ctx context.Context, tx *sql.Tx, source int64, ids []int64) (investigationBusinessMove, error) {
	p := investigationBusinessMove{source: source, users: map[int64]bool{}}
	for _, id := range ids {
		p.users[id] = true
	}
	var err error
	p.base, err = usersvc.DispatchEntriesBeforeInvestigationFrom(ctx, tx)
	if err != nil {
		return p, err
	}
	p.assignments, err = usersvc.LoadInvestigationAssignments(ctx, tx, 0)
	return p, err
}

func (p investigationBusinessMove) verify(ctx context.Context, tx *sql.Tx, before, after []usersvc.DispatchEntry, target InvestigationGroup) error {
	expected := append([]usersvc.InvestigationAssignment{}, p.assignments...)
	moved := map[int64]bool{}
	for i, a := range expected {
		if a.GroupID == p.source && p.users[a.UserID] {
			expected[i].GroupID, expected[i].Host, expected[i].Generation = target.ID, target.Host, target.Generation
			moved[a.UserID] = true
		}
	}
	if !reflect.DeepEqual(moved, p.users) {
		return splitEditInvalid("迁移成员下发关系已变化，已回滚")
	}
	actual, err := usersvc.LoadInvestigationAssignments(ctx, tx, 0)
	if err != nil {
		return err
	}
	// Compare every assignment as well as the final address sets: checking only
	// hosts cannot detect a user moved to the wrong group at the same endpoint.
	ordered := func(a []usersvc.InvestigationAssignment) []usersvc.InvestigationAssignment {
		out := append([]usersvc.InvestigationAssignment{}, a...)
		sort.Slice(out, func(i, j int) bool {
			x, y := out[i], out[j]
			if x.RootID != y.RootID {
				return x.RootID < y.RootID
			}
			if x.UserID != y.UserID {
				return x.UserID < y.UserID
			}
			if x.OriginHost != y.OriginHost {
				return x.OriginHost < y.OriginHost
			}
			return x.GroupID < y.GroupID
		})
		return out
	}
	if !reflect.DeepEqual(ordered(expected), ordered(actual)) {
		return splitEditInvalid("迁移改变了预期之外的业务下发关系，已回滚")
	}
	byUser := map[int64][]usersvc.InvestigationAssignment{}
	for _, a := range expected {
		if p.users[a.UserID] {
			byUser[a.UserID] = append(byUser[a.UserID], a)
		}
	}
	wanted := map[int64]map[string]bool{}
	for id := range p.users {
		hosts := map[string]bool{}
		for _, entry := range p.base {
			if !usersvc.DispatchEntryContains(entry, id) {
				continue
			}
			host := entry.Host
			for _, a := range byUser[id] {
				if a.OriginHost == "*" || a.OriginHost == entry.Host {
					host = a.Host
					break
				}
			}
			hosts[host] = true
		}
		if !hosts[target.Host] {
			return splitEditInvalid("目标入口没有实际下发给迁移成员，已回滚")
		}
		wanted[id] = hosts
	}
	return verifyInvestigationMemberEdit(before, after, wanted)
}

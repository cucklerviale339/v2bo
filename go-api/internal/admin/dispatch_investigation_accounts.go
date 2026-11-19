package admin

import (
	"context"

	usersvc "forest/go-api/internal/user"
)

// One immutable dispatch catalog, within one phase of an action. Discard this
// cache before commit-time validation: accounts may have been deleted while
// the action was running even though address writers are locked out.
type investigationDispatchAccounts struct {
	q   usersvc.DispatchQueryer
	ids map[string][]int64
}

func newInvestigationDispatchAccounts(q usersvc.DispatchQueryer) *investigationDispatchAccounts {
	return &investigationDispatchAccounts{q: q, ids: map[string][]int64{}}
}

func (a *investigationDispatchAccounts) load(ctx context.Context, entry usersvc.DispatchEntry) ([]int64, error) {
	if ids, ok := a.ids[entry.Host]; ok {
		return ids, nil
	}
	ids, err := usersvc.DispatchAccountIDs(ctx, a.q, entry)
	if err == nil {
		a.ids[entry.Host] = ids
	}
	return ids, err
}

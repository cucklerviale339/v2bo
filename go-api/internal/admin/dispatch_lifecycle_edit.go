package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	usersvc "forest/go-api/internal/user"
)

type investigationMemberEdit struct {
	Changed        bool
	Added, Removed []int64
	ExpectedHosts  map[int64]map[string]bool
}

// Edits transfer only existing, effective business assignments. They cannot
// turn a partial-node assignment into an all-node override. Removing a member
// releases this group's assignments back to the original business selectors.
func editInvestigationMembers(ctx context.Context, tx *sql.Tx, g InvestigationGroup, v *InvestigationEdit) (investigationMemberEdit, error) {
	out := investigationMemberEdit{}
	if v.UserIDs == nil {
		return out, nil
	}
	if g.RouteScope != "business" || (g.LifecycleRole != "stable" && g.LifecycleRole != "whitelist") {
		return out, splitEditInvalid("仅稳定组和老实人组支持编辑成员")
	}
	if len(*v.UserIDs) == 0 || len(*v.UserIDs) > 20000 {
		return out, splitEditInvalid("请填写1至20000个具体用户ID，至少保留一名成员")
	}
	wanted := map[int64]bool{}
	ids := []int64{}
	for _, raw := range *v.UserIDs {
		id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err != nil || id < 1 {
			return out, splitEditInvalid("成员必须是具体用户ID，不支持ID范围")
		}
		if !wanted[id] {
			wanted[id] = true
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	normalized := make([]string, len(ids))
	for i, id := range ids {
		normalized[i] = strconv.FormatInt(id, 10)
	}
	v.UserIDs = &normalized
	if g.Kind == "confirmed" {
		v.ManualOnly = true
	}
	rawIDs, _ := json.Marshal(ids)
	// Keep account deletion from racing the projection and the final commit.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM v2_user WHERE id IN(SELECT value::bigint FROM jsonb_array_elements_text($1::jsonb)) ORDER BY id FOR KEY SHARE`, string(rawIDs))
	if err != nil {
		return out, err
	}
	count := 0
	for rows.Next() {
		count++
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if count != len(ids) {
		return out, splitEditInvalid("成员中有不存在或已删除的用户")
	}
	base, err := usersvc.DispatchEntriesBeforeInvestigationFrom(ctx, tx)
	if err != nil {
		return out, err
	}
	assignments, err := usersvc.LoadInvestigationAssignments(ctx, tx, 0)
	if err != nil {
		return out, err
	}
	baseByHost := map[string]usersvc.DispatchEntry{}
	for _, entry := range base {
		baseByHost[entry.Host] = entry
	}
	existing := map[int64]bool{}
	for _, id := range investigationGroupIDs(g) {
		existing[id] = true
		if !wanted[id] {
			out.Removed = append(out.Removed, id)
		}
	}
	added := map[int64]bool{}
	for _, id := range ids {
		if !existing[id] {
			added[id] = true
			out.Added = append(out.Added, id)
		}
	}
	// Omitted inactive assignments also leave the editable, explicit roster;
	// temporarily disabling a rule must not silently re-add a removed user later.
	var omitted bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id NOT IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)))`, g.ID, string(rawIDs)).Scan(&omitted); err != nil {
		return out, err
	}
	out.Changed = len(out.Added) > 0 || omitted
	if !out.Changed && v.Host == g.Host {
		return out, nil
	}
	type transfer struct {
		RootID int64  `json:"root_id"`
		Origin string `json:"origin_host"`
		UserID int64  `json:"user_id"`
		Source int64  `json:"group_id"`
	}
	transfers := []transfer{}
	found := map[int64]bool{}
	sources := map[int64]map[int64]bool{}
	expectedAssignments := []usersvc.InvestigationAssignment{}
	for _, a := range assignments {
		if added[a.UserID] {
			if a.OriginHost == "*" {
				return out, splitEditInvalid(fmt.Sprintf("用户%d仍由旧全站分组管理，请先退出全站管理", a.UserID))
			}
			if usersvc.DispatchEntryContains(baseByHost[a.OriginHost], a.UserID) {
				found[a.UserID] = true
				if a.GroupID != g.ID {
					transfers = append(transfers, transfer{a.RootID, a.OriginHost, a.UserID, a.GroupID})
					if sources[a.GroupID] == nil {
						sources[a.GroupID] = map[int64]bool{}
					}
					sources[a.GroupID][a.UserID] = true
				}
				a.GroupID, a.Host = g.ID, v.Host
			}
		}
		if a.GroupID == g.ID {
			if !wanted[a.UserID] {
				continue
			}
			a.Host = v.Host
		}
		expectedAssignments = append(expectedAssignments, a)
	}
	for _, id := range out.Added {
		if !found[id] {
			return out, splitEditInvalid(fmt.Sprintf("用户%d没有当前有效的入口分组，请先纳入入口监控", id))
		}
	}
	// Calculate each changed user's complete host set, including their unrelated
	// nodes. A catalog-level move from a single old IP would lose that distinction.
	out.ExpectedHosts = map[int64]map[string]bool{}
	for id := range existing {
		out.ExpectedHosts[id] = map[string]bool{}
	}
	for id := range wanted {
		out.ExpectedHosts[id] = map[string]bool{}
	}
	byUser := map[int64][]usersvc.InvestigationAssignment{}
	for _, a := range expectedAssignments {
		byUser[a.UserID] = append(byUser[a.UserID], a)
	}
	for id, hosts := range out.ExpectedHosts {
		for _, entry := range base {
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
	}
	// Reset only entrants' personal clocks. Existing members keep their earned
	// days; a returning member cannot reuse a receipt from a previous admission.
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_stability_receipt d USING v2_dispatch_investigation_member m WHERE m.group_id=$1 AND m.user_id NOT IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb)) AND d.origin_host=m.origin_host AND d.user_id=m.user_id`, g.ID, string(rawIDs)); err != nil {
		return out, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1 AND user_id NOT IN(SELECT value::bigint FROM jsonb_array_elements_text($2::jsonb))`, g.ID, string(rawIDs)); err != nil {
		return out, err
	}
	if len(transfers) > 0 {
		raw, _ := json.Marshal(transfers)
		if _, err = tx.ExecContext(ctx, `DELETE FROM v2_dispatch_stability_receipt d USING jsonb_to_recordset($1::jsonb) x(root_id bigint,origin_host text,user_id bigint,group_id bigint) WHERE d.origin_host=x.origin_host AND d.user_id=x.user_id`, string(raw)); err != nil {
			return out, err
		}
		result, e := tx.ExecContext(ctx, `UPDATE v2_dispatch_investigation_member m SET group_id=$2 FROM jsonb_to_recordset($1::jsonb) x(root_id bigint,origin_host text,user_id bigint,group_id bigint) WHERE m.root_id=x.root_id AND m.origin_host=x.origin_host AND m.user_id=x.user_id AND m.group_id=x.group_id`, string(raw), g.ID)
		if e != nil {
			return out, e
		}
		if n, e := result.RowsAffected(); e != nil || n != int64(len(transfers)) {
			return out, splitEditInvalid("成员下发关系已变化，请刷新后重试")
		}
	}
	for source, sourceMembers := range sources {
		var sourceRoot int64
		if err = tx.QueryRowContext(ctx, `UPDATE v2_dispatch_investigation_group SET revision=revision+1 WHERE id=$1 RETURNING root_id`, source).Scan(&sourceRoot); err != nil {
			return out, err
		}
		sourceIDs := []int64{}
		for id := range sourceMembers {
			sourceIDs = append(sourceIDs, id)
		}
		sort.Slice(sourceIDs, func(i, j int) bool { return sourceIDs[i] < sourceIDs[j] })
		if err = investigationAudit(ctx, tx, sourceRoot, source, "members_moved", 0, map[string]any{"target_group_id": g.ID, "user_ids": sourceIDs}); err != nil {
			return out, err
		}
	}
	return out, nil
}

func verifyInvestigationMemberEdit(before, after []usersvc.DispatchEntry, expected map[int64]map[string]bool) error {
	masks := make([]splitEditSpan, 0, len(expected))
	for id, hosts := range expected {
		masks = append(masks, splitEditSpan{id, id})
		got := map[string]bool{}
		for _, entry := range after {
			if usersvc.DispatchEntryContains(entry, id) {
				got[entry.Host] = true
			}
		}
		if !reflect.DeepEqual(hosts, got) {
			return splitEditInvalid("成员实际下发与预期不一致，已回滚")
		}
	}
	if !reflect.DeepEqual(splitScopesOutside(before, masks), splitScopesOutside(after, masks)) {
		return splitEditInvalid("修改影响了其他用户的下发，已回滚")
	}
	return nil
}

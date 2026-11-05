package user

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"forest/go-api/internal/platform/addrutil"
	"forest/go-api/internal/platform/userselector"
	"forest/go-api/internal/subscribelink"
)

type DispatchQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// DispatchEntry describes configured ID ownership, not account eligibility.
// IDs remain strings so JavaScript cannot round large identifiers.
type DispatchEntry struct {
	Host         string   `json:"host"`
	UserIDs      []string `json:"user_ids"`
	UserIDRanges []string `json:"user_id_ranges"`
	Sources      []string `json:"sources"`
}

type dispatchSpan struct{ start, end int64 }
type dispatchOwnership struct {
	spans   []dispatchSpan
	sources map[string]struct{}
}
type dispatchRuleScope struct {
	rule  nodeAddressRule
	spans []dispatchSpan
}

// DispatchEntries projects enabled nodes and address rules over the positive ID space.
// Original rules ignore account existence, permissions, status, UA, plan and age;
// investigation overrides apply only to accounts that still exist.
func (s *DBService) DispatchEntries(ctx context.Context) ([]DispatchEntry, error) {
	if s.db == nil {
		return nil, ErrUnavailable
	}
	if err := s.ensureNodeAddressSchema(ctx); err != nil {
		return nil, err
	}
	return DispatchEntriesFrom(ctx, s.db)
}

// DispatchEntriesFrom uses the same address selectors inside an already initialized transaction.
func DispatchEntriesFrom(ctx context.Context, q DispatchQueryer) ([]DispatchEntry, error) {
	entries, _, err := DispatchEntriesWithInvestigationMembersFrom(ctx, q)
	return entries, err
}

// Return ownership and effective investigation members from the same projection.
// A shared destination alone cannot admit members whose original source vanished.
func DispatchEntriesWithInvestigationMembersFrom(ctx context.Context, q DispatchQueryer) ([]DispatchEntry, map[int64]InvestigationMembers, error) {
	entries, err := DispatchEntriesBeforeInvestigationFrom(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	return investigationCatalog(ctx, q, entries)
}

// Original configured ownership, before investigation assignments split it.
func DispatchEntriesBeforeInvestigationFrom(ctx context.Context, q DispatchQueryer) ([]DispatchEntry, error) {
	addresses, err := loadNodeAddressSelectorFrom(ctx, q)
	if err != nil {
		return nil, err
	}
	insiders, err := loadInsiderSelectorFrom(ctx, q)
	if err != nil {
		return nil, err
	}
	servers := make([]map[string]any, 0)
	for _, table := range serverFetchTables {
		rows, err := q.QueryContext(ctx, `SELECT id, host FROM `+table.table+` WHERE "show" = 1 ORDER BY id ASC`)
		if err != nil {
			return nil, fmt.Errorf("query dispatch node addresses: %w", err)
		}
		for rows.Next() {
			var id int64
			var host string
			if err := rows.Scan(&id, &host); err != nil {
				rows.Close()
				return nil, err
			}
			servers = append(servers, map[string]any{"id": id, "host": host, "type": table.serverType})
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return configuredDispatchEntries(ctx, servers, addresses, insiders)
}

func configuredDispatchEntries(ctx context.Context, servers []map[string]any, addresses *nodeAddressSelector, insiders *insiderSelector) ([]DispatchEntry, error) {
	insiderRules := make([]nodeAddressRule, 0)
	if insiders != nil {
		for _, rule := range insiders.rules {
			insiderRules = append(insiderRules, rule.nodeAddressRule)
		}
	}
	insiderScopes, insiderCovered := dispatchRuleScopes(insiderRules)
	entries := make(map[string]*dispatchOwnership)
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		base, _ := server["host"].(string)
		for _, scope := range insiderScopes {
			host, keep := dispatchManagedHost(scope.rule, base, true)
			if keep {
				addDispatchOwnership(entries, host, scope.spans, fmt.Sprintf("内鬼管理规则 #%d", scope.rule.ID))
			}
		}
		var nodeRules []nodeAddressRule
		if addresses != nil {
			group := addresses.bindings[nodeAddressServerKey(fmt.Sprint(server["type"]), mapInt64(server["id"]))]
			nodeRules = addresses.rules[group]
		}
		addressScopes, addressCovered := dispatchRuleScopes(nodeRules)
		for _, scope := range addressScopes {
			host, keep := dispatchManagedHost(scope.rule, base, false)
			if keep {
				addDispatchOwnership(entries, host, subtractDispatchSpans(scope.spans, insiderCovered), fmt.Sprintf("节点地址规则 #%d", scope.rule.ID))
			}
		}
		remaining := subtractDispatchSpans([]dispatchSpan{{1, math.MaxInt64}}, mergeDispatchSpans(append(append([]dispatchSpan{}, insiderCovered...), addressCovered...)))
		addDispatchOwnership(entries, base, remaining, fmt.Sprintf("节点管理 %s #%v", server["type"], server["id"]))
	}
	result := make([]DispatchEntry, 0, len(entries))
	for host, ownership := range entries {
		entry := DispatchEntry{Host: host, UserIDs: []string{}, UserIDRanges: []string{}, Sources: []string{}}
		for _, span := range mergeDispatchSpans(ownership.spans) {
			if span.start == span.end {
				entry.UserIDs = append(entry.UserIDs, strconv.FormatInt(span.start, 10))
			} else {
				entry.UserIDRanges = append(entry.UserIDRanges, fmt.Sprintf("%d-%d", span.start, span.end))
			}
		}
		for source := range ownership.sources {
			entry.Sources = append(entry.Sources, source)
		}
		sort.Strings(entry.Sources)
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Host < result[j].Host })
	return result, nil
}

// Mirror Resolve/ResolveRule: all exact-ID matches precede all range matches;
// the first matching rule within each pass owns that portion of the ID space.
func dispatchRuleScopes(rules []nodeAddressRule) ([]dispatchRuleScope, []dispatchSpan) {
	result := make([]dispatchRuleScope, 0)
	var covered []dispatchSpan
	for pass := 0; pass < 2; pass++ {
		for _, rule := range rules {
			var spans []dispatchSpan
			if pass == 0 {
				for _, token := range rule.MatchUserIDs {
					for _, part := range strings.Split(token, ",") {
						id, err := strconv.ParseInt(strings.TrimSpace(strings.Trim(part, `"'`)), 10, 64)
						if err == nil && id > 0 {
							spans = append(spans, dispatchSpan{id, id})
						}
					}
				}
			} else {
				for _, token := range rule.MatchUserIDRanges {
					for _, part := range strings.Split(token, ",") {
						if start, end, ok := userselector.ParseRange(part); ok {
							spans = append(spans, dispatchSpan{start, end})
						}
					}
				}
			}
			spans = mergeDispatchSpans(spans)
			owned := subtractDispatchSpans(spans, covered)
			if len(owned) > 0 {
				result = append(result, dispatchRuleScope{rule, owned})
			}
			covered = mergeDispatchSpans(append(covered, spans...))
		}
	}
	return result, covered
}

// Extra nodes themselves are excluded. Respect whether their configured mode
// retains a managed node so replaced nodes do not reappear as monitored hosts.
func dispatchManagedHost(rule nodeAddressRule, base string, insider bool) (string, bool) {
	if len(rule.ExtraNodes) > 0 {
		if rule.ExtraNodesPosition != subscribelink.PositionBefore {
			return "", false
		}
		if !insider {
			return base, true
		}
	}
	if rule.Host != "" {
		return rule.Host, true
	}
	return base, true
}

func addDispatchOwnership(entries map[string]*dispatchOwnership, config string, spans []dispatchSpan, source string) {
	if len(spans) == 0 {
		return
	}
	// Conditional node-address values are inventoried without evaluating their
	// UA/plan/registration-day predicates, as requested by the monitor UI.
	for _, raw := range strings.Split(config, ",") {
		host := strings.TrimSpace(strings.SplitN(raw, "(", 2)[0])
		if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && address.Zone() == "" {
			host = address.String()
		} else {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
		}
		if !addrutil.IsIPOrHostname(host) {
			continue
		}
		entry := entries[host]
		if entry == nil {
			entry = &dispatchOwnership{sources: make(map[string]struct{})}
			entries[host] = entry
		}
		entry.spans = append(entry.spans, spans...)
		entry.sources[source] = struct{}{}
	}
}

func mergeDispatchSpans(spans []dispatchSpan) []dispatchSpan {
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	result := make([]dispatchSpan, 0, len(spans))
	for _, span := range spans {
		if len(result) > 0 {
			last := &result[len(result)-1]
			if span.start <= last.end || (last.end < math.MaxInt64 && span.start == last.end+1) {
				if span.end > last.end {
					last.end = span.end
				}
				continue
			}
		}
		result = append(result, span)
	}
	return result
}

func subtractDispatchSpans(spans, excluded []dispatchSpan) []dispatchSpan {
	result := make([]dispatchSpan, 0)
	for _, span := range spans {
		start := span.start
		consumed := false
		for _, cut := range excluded {
			if cut.end < start {
				continue
			}
			if cut.start > span.end {
				break
			}
			if cut.start > start {
				result = append(result, dispatchSpan{start, cut.start - 1})
			}
			if cut.end >= span.end {
				consumed = true
				break
			}
			start = cut.end + 1
		}
		if !consumed && start <= span.end {
			result = append(result, dispatchSpan{start, span.end})
		}
	}
	return result
}

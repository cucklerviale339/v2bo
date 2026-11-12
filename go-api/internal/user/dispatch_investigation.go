package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"forest/go-api/internal/platform/userselector"
)

// The host serializes as an ordinary string. The private round identity follows
// the actual rendered server, so a late response cannot credit a newer round.
type InvestigationHost struct {
	Value               string
	GroupID, Generation int64
}

func (h InvestigationHost) String() string               { return h.Value }
func (h InvestigationHost) MarshalJSON() ([]byte, error) { return json.Marshal(h.Value) }

type InvestigationAssignment struct {
	GroupID, RootID, UserID, Generation int64
	OriginHost, Host                    string
}

type InvestigationMembers struct {
	Host string
	IDs  map[int64]bool
}

func NormalizeDispatchHost(host string) string {
	host = strings.TrimSpace(host)
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && ip.Zone() == "" {
		return ip.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func DispatchEntryContains(e DispatchEntry, id int64) bool {
	return userselector.MatchesIDs(e.UserIDs, id) || userselector.MatchesRanges(e.UserIDRanges, id)
}

func LoadInvestigationAssignments(ctx context.Context, q DispatchQueryer, userID int64) ([]InvestigationAssignment, error) {
	// A frozen roster can outlive an account. Apply overrides only to accounts
	// that still exist, matching the roster used by automatic and manual actions.
	// The underlying configured ID ranges remain independent of account state.
	rows, err := q.QueryContext(ctx, `SELECT m.group_id,m.root_id,m.user_id,m.origin_host,g.host,g.generation FROM v2_dispatch_investigation_member m JOIN v2_user u ON u.id=m.user_id JOIN v2_dispatch_investigation_group g ON g.id=m.group_id WHERE g.active AND g.route_scope='business' AND ($1::bigint=0 OR m.user_id=$1)
AND NOT EXISTS(SELECT 1 FROM v2_dispatch_global_member w JOIN v2_dispatch_investigation_group wg ON wg.id=w.group_id AND wg.active WHERE w.user_id=m.user_id)
UNION ALL
SELECT g.id,g.root_id,w.user_id,'*',g.host,g.generation FROM v2_dispatch_global_member w JOIN v2_user u ON u.id=w.user_id JOIN v2_dispatch_investigation_group g ON g.id=w.group_id WHERE g.active AND g.route_scope='global' AND ($1::bigint=0 OR w.user_id=$1)
ORDER BY 2,3`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []InvestigationAssignment{}
	for rows.Next() {
		var v InvestigationAssignment
		if err = rows.Scan(&v.GroupID, &v.RootID, &v.UserID, &v.OriginHost, &v.Host, &v.Generation); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func applyInvestigationAssignment(item map[string]any, assignments []InvestigationAssignment) {
	host := NormalizeDispatchHost(fmt.Sprint(item["host"]))
	for _, a := range assignments {
		if a.OriginHost == "*" || a.OriginHost == host {
			item["host"] = InvestigationHost{Value: a.Host, GroupID: a.GroupID, Generation: a.Generation}
			return
		}
	}
}

// Apply only to ownership already produced by the existing three address
// layers. Disabled/removed rules and nodes therefore do not reappear here.
func investigationCatalog(ctx context.Context, q DispatchQueryer, entries []DispatchEntry) ([]DispatchEntry, map[int64]InvestigationMembers, error) {
	assignments, err := LoadInvestigationAssignments(ctx, q, 0)
	if err != nil {
		return nil, nil, err
	}
	byHost := map[string]DispatchEntry{}
	for _, e := range entries {
		byHost[e.Host] = e
	}
	result := map[string]*dispatchOwnership{}
	masks := map[string][]dispatchSpan{}
	members := map[int64]InvestigationMembers{}
	for _, a := range assignments {
		if a.OriginHost == "*" {
			matched := false
			for _, e := range entries {
				if DispatchEntryContains(e, a.UserID) {
					masks[e.Host] = append(masks[e.Host], dispatchSpan{a.UserID, a.UserID})
					matched = true
				}
			}
			if matched {
				if members[a.GroupID].IDs == nil {
					members[a.GroupID] = InvestigationMembers{Host: a.Host, IDs: map[int64]bool{}}
				}
				members[a.GroupID].IDs[a.UserID] = true
				addDispatchOwnership(result, a.Host, []dispatchSpan{{a.UserID, a.UserID}}, fmt.Sprintf("谁是卧底 #%d", a.GroupID))
			}
			continue
		}
		original, ok := byHost[a.OriginHost]
		if !ok || !DispatchEntryContains(original, a.UserID) {
			continue
		}
		if members[a.GroupID].IDs == nil {
			members[a.GroupID] = InvestigationMembers{Host: a.Host, IDs: map[int64]bool{}}
		}
		members[a.GroupID].IDs[a.UserID] = true
		masks[a.OriginHost] = append(masks[a.OriginHost], dispatchSpan{a.UserID, a.UserID})
		addDispatchOwnership(result, a.Host, []dispatchSpan{{a.UserID, a.UserID}}, fmt.Sprintf("谁是卧底 #%d", a.GroupID))
	}
	for _, e := range entries {
		spans := []dispatchSpan{}
		for _, raw := range e.UserIDs {
			n, _ := strconv.ParseInt(raw, 10, 64)
			spans = append(spans, dispatchSpan{n, n})
		}
		for _, raw := range e.UserIDRanges {
			a, b, ok := userselector.ParseRange(raw)
			if ok {
				spans = append(spans, dispatchSpan{a, b})
			}
		}
		spans = subtractDispatchSpans(mergeDispatchSpans(spans), mergeDispatchSpans(masks[e.Host]))
		for _, source := range e.Sources {
			addDispatchOwnership(result, e.Host, spans, source)
		}
	}
	out := []DispatchEntry{}
	for host, v := range result {
		e := DispatchEntry{Host: host, UserIDs: []string{}, UserIDRanges: []string{}, Sources: []string{}}
		for _, span := range mergeDispatchSpans(v.spans) {
			if span.start == span.end {
				e.UserIDs = append(e.UserIDs, strconv.FormatInt(span.start, 10))
			} else {
				e.UserIDRanges = append(e.UserIDRanges, fmt.Sprintf("%d-%d", span.start, span.end))
			}
		}
		for source := range v.sources {
			e.Sources = append(e.Sources, source)
		}
		sort.Strings(e.Sources)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, members, nil
}

type InvestigationDelivery struct {
	GroupID    int64  `json:"group_id"`
	Generation int64  `json:"generation"`
	Host       string `json:"host"`
}

var investigationDeliveryFailure atomic.Int64

func InvestigationDeliveryFailureAt() int64 { return investigationDeliveryFailure.Load() }

// Only called after a complete successful HTTP body write, with hosts parsed
// from that body. This is server delivery evidence, not a client read receipt.
func (s *DBService) RecordInvestigationDelivery(ctx context.Context, userID int64, entries []InvestigationDelivery, at int64) error {
	if s == nil || s.db == nil || userID <= 0 || len(entries) == 0 {
		return nil
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `WITH eligible AS (
SELECT DISTINCT g.id,g.generation,$2::bigint,$3::bigint FROM jsonb_to_recordset($1::jsonb) e(group_id bigint,generation bigint,host text)
JOIN v2_dispatch_investigation_group g ON g.id=e.group_id AND g.generation=e.generation AND g.host=e.host AND g.active
JOIN v2_dispatch_investigation_settings s ON s.id=1 AND s.enabled AND $3>=s.armed_at
WHERE $3>=g.epoch_at AND (EXISTS(SELECT 1 FROM v2_dispatch_investigation_member m WHERE m.group_id=g.id AND m.user_id=$2) OR EXISTS(SELECT 1 FROM v2_dispatch_global_member w WHERE w.group_id=g.id AND w.user_id=$2))), first_delivery AS (
INSERT INTO v2_dispatch_investigation_delivery(group_id,generation,user_id,delivered_at)
SELECT * FROM eligible ON CONFLICT(group_id,generation,user_id) DO UPDATE SET delivered_at=LEAST(EXCLUDED.delivered_at,v2_dispatch_investigation_delivery.delivered_at)), recent_delivery AS (
INSERT INTO v2_dispatch_investigation_delivery_recent(group_id,generation,user_id,delivered_at)
SELECT * FROM eligible ON CONFLICT DO NOTHING), stability AS (
INSERT INTO v2_dispatch_stability_receipt(origin_host,user_id,host,first_at,last_at)
SELECT DISTINCT m.origin_host,$2::bigint,g.host,$3::bigint,$3::bigint FROM eligible e
JOIN v2_dispatch_investigation_group g ON g.id=e.id
JOIN v2_dispatch_investigation_member m ON m.group_id=g.id AND m.user_id=$2
JOIN v2_dispatch_investigation_settings s ON s.id=1 AND s.lifecycle_enabled AND $3>=s.lifecycle_started_at
ON CONFLICT(origin_host,user_id) DO UPDATE SET host=EXCLUDED.host,
first_at=CASE WHEN v2_dispatch_stability_receipt.host=EXCLUDED.host THEN LEAST(v2_dispatch_stability_receipt.first_at,EXCLUDED.first_at) ELSE EXCLUDED.first_at END,
last_at=EXCLUDED.last_at WHERE EXCLUDED.last_at>=v2_dispatch_stability_receipt.last_at)
INSERT INTO v2_dispatch_host_exposure(host,user_id,first_at,last_at)
SELECT DISTINCT host,$2::bigint,$3::bigint,$3::bigint FROM jsonb_to_recordset($1::jsonb) e(group_id bigint,generation bigint,host text)
WHERE e.group_id>0 OR EXISTS(SELECT 1 FROM v2_dispatch_investigation_settings WHERE id=1 AND enabled AND lifecycle_enabled)
ON CONFLICT(host,user_id) DO UPDATE SET first_at=LEAST(v2_dispatch_host_exposure.first_at,EXCLUDED.first_at),last_at=GREATEST(v2_dispatch_host_exposure.last_at,EXCLUDED.last_at)`, string(raw), userID, at)
	if err != nil {
		investigationDeliveryFailure.Store(time.Now().Unix())
	}
	return err
}

func (s *DBService) MarkInvestigationDeliveryFailure(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE v2_dispatch_investigation_health SET delivery_failure_at=$1 WHERE id=1`, time.Now().Unix())
	return err
}

// Shared by both automatic systems: an actual singleton never gets an
// automatic address, even when its configured numeric range contains more IDs.
func DispatchAccountIDs(ctx context.Context, q DispatchQueryer, e DispatchEntry) ([]int64, error) {
	spans := []map[string]int64{}
	for _, v := range e.UserIDs {
		n, err := strconv.ParseInt(v, 10, 64)
		if err == nil && n > 0 {
			spans = append(spans, map[string]int64{"a": n, "b": n})
		}
	}
	for _, v := range e.UserIDRanges {
		a, b, ok := userselector.ParseRange(v)
		if ok {
			spans = append(spans, map[string]int64{"a": a, "b": b})
		}
	}
	raw, _ := json.Marshal(spans)
	rows, err := q.QueryContext(ctx, `SELECT u.id FROM v2_user u WHERE EXISTS(SELECT 1 FROM jsonb_to_recordset($1::jsonb) x(a bigint,b bigint) WHERE u.id BETWEEN x.a AND x.b) ORDER BY u.id`, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

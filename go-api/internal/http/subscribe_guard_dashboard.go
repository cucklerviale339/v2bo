package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/subscribeguard"
)

type subscriptionGuardAnalytics interface {
	Analytics(context.Context, int64) (map[string]any, error)
	Users(context.Context, string, string, int64, int64) (map[string]any, error)
	CrawlerUsers(context.Context, int64, int64) (map[string]any, error)
}

func guardPublicUser(info map[string]any) map[string]any {
	result := map[string]any{}
	for _, key := range []string{"id", "email", "banned", "deleted_user", "plan_id", "plan_name", "group_id", "group_name", "u", "d", "transfer_enable", "device_limit", "expired_at", "t", "last_login_at", "balance", "commission_balance", "speed_limit", "invite_user_id", "invite_code", "created_at", "remarks", "is_admin", "is_staff"} {
		if value, ok := info[key]; ok {
			result[key] = value
		}
	}
	return result
}

func guardInsiderMatch(rules []admin.InsiderRuleRecord, userID int64) any {
	if userID <= 0 {
		return nil
	}
	public := func(rule admin.InsiderRuleRecord) any {
		return map[string]any{"id": rule.ID, "name": rule.Name, "host": rule.Host, "extra_nodes_count": len(rule.ExtraNodes), "extra_nodes_position": rule.ExtraNodesPosition}
	}
	for _, rule := range rules {
		if rule.Enabled != 1 {
			continue
		}
		for _, value := range rule.MatchUserIDs {
			for _, part := range strings.Split(value, ",") {
				parsed, err := strconv.ParseInt(strings.TrimSpace(strings.Trim(part, `"'`)), 10, 64)
				if err == nil && parsed == userID {
					return public(rule)
				}
			}
		}
	}
	for _, rule := range rules {
		if rule.Enabled != 1 {
			continue
		}
		for _, value := range rule.MatchUserIDRanges {
			for _, part := range strings.Split(value, ",") {
				bounds := strings.Split(strings.TrimSpace(strings.Trim(part, `"'`)), "-")
				if len(bounds) != 2 {
					continue
				}
				lower, lowerErr := strconv.ParseInt(strings.TrimSpace(bounds[0]), 10, 64)
				upper, upperErr := strconv.ParseInt(strings.TrimSpace(bounds[1]), 10, 64)
				if lower > upper {
					lower, upper = upper, lower
				}
				if lowerErr == nil && upperErr == nil && lower > 0 && userID >= lower && userID <= upper {
					return public(rule)
				}
			}
		}
	}
	return nil
}

func handleSubscribeGuardDashboard(w http.ResponseWriter, r *http.Request, state *routerState, action string) {
	disableResponseCache(w)
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	method := http.MethodGet
	if action == "set-user-banned" {
		method = http.MethodPost
	}
	if r.Method != method {
		writeJSON(w, 405, map[string]any{"message": "请求方式不支持"})
		return
	}
	identity, ok := authenticateRequest(w, r, state.session, true)
	if !ok {
		return
	}
	analytics, ok := state.subscribeGuard.(subscriptionGuardAnalytics)
	if !ok || state.admin == nil {
		writeJSON(w, 503, map[string]any{"message": "订阅防护统计未就绪"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"message": "参数无效"})
		return
	}
	keyword := strings.TrimSpace(inputs["keyword"])
	if len(keyword) > 255 {
		writeJSON(w, 400, map[string]any{"message": "搜索内容过长"})
		return
	}
	userID, _ := strconv.ParseInt(inputs["id"], 10, 64)
	var result any
	switch action {
	case "stats":
		result, err = analytics.Analytics(ctx, 0)
	case "user-rank", "ua-search", "crawler-users":
		sort := inputs["sort"]
		if sort == "" {
			sort = "count"
		}
		current, size := int64(1), int64(20)
		if value := inputs["current"]; value != "" {
			current, _ = strconv.ParseInt(value, 10, 64)
		}
		if value := inputs["page_size"]; value != "" {
			size, _ = strconv.ParseInt(value, 10, 64)
		}
		if (sort != "count" && sort != "ip_count") || current < 1 || current > 100000 || size < 1 || size > 100 || (action == "ua-search" && keyword == "") {
			writeJSON(w, 400, map[string]any{"message": "分页或排序参数无效"})
			return
		}
		if action == "user-rank" {
			keyword = ""
		}
		if action == "crawler-users" {
			result, err = analytics.CrawlerUsers(ctx, current, size)
		} else {
			result, err = analytics.Users(ctx, keyword, sort, current, size)
		}
	case "user-search":
		rows := []map[string]any{}
		if keyword == "" {
			result = rows
			break
		}
		filter := admin.UserFilter{Key: "email", Condition: "模糊", Value: keyword}
		if id, parseErr := strconv.ParseInt(keyword, 10, 64); parseErr == nil && id > 0 {
			filter = admin.UserFilter{Key: "id", Condition: "=", Value: keyword}
		}
		var users admin.UserListResult
		users, err = state.admin.ListUsers(ctx, admin.UserFetchRequest{Current: 1, PageSize: 20, Sort: "id", SortType: "DESC", Filters: []admin.UserFilter{filter}})
		if err != nil {
			break
		}
		var rules []admin.InsiderRuleRecord
		rules, err = state.admin.ListInsiderRules(ctx)
		if err != nil {
			break
		}
		for _, user := range users.Data {
			row := guardPublicUser(user)
			row["insider_rule"] = guardInsiderMatch(rules, anyInt64(user["id"]))
			rows = append(rows, row)
		}
		result = rows
	case "user-detail":
		if userID <= 0 {
			writeJSON(w, 400, map[string]any{"message": "用户 ID 无效"})
			return
		}
		var info, stats, events map[string]any
		info, err = state.admin.GetUserInfoByID(ctx, userID)
		if err != nil {
			break
		}
		stats, err = analytics.Analytics(ctx, userID)
		if err != nil {
			break
		}
		events, err = state.subscribeGuard.Events(ctx, subscribeguard.Filter{UserID: userID, Limit: 50})
		if err != nil {
			break
		}
		var rules []admin.InsiderRuleRecord
		rules, err = state.admin.ListInsiderRules(ctx)
		row := guardPublicUser(info)
		row["insider_rule"] = guardInsiderMatch(rules, userID)
		result = map[string]any{"user": row, "stats": stats, "recent": events["data"]}
	case "set-user-banned":
		banned, parseErr := strconv.ParseInt(inputs["banned"], 10, 64)
		if userID <= 0 || parseErr != nil || (banned != 0 && banned != 1) {
			writeJSON(w, 400, map[string]any{"message": "用户或账号状态无效"})
			return
		}
		var info map[string]any
		info, err = state.admin.GetUserInfoByID(ctx, userID)
		if err != nil {
			break
		}
		if anyInt64(info["deleted_user"]) != 0 {
			writeJSON(w, 400, map[string]any{"message": "用户不存在"})
			return
		}
		if banned == 1 && (userID == identity.ID || anyInt64(info["is_admin"]) != 0 || anyInt64(info["is_staff"]) != 0) {
			writeJSON(w, 400, map[string]any{"message": "不能在订阅防护中封禁自己、管理员或员工账号"})
			return
		}
		result, err = state.admin.SetUserBanned(ctx, userID, banned)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeJSON(w, 503, map[string]any{"message": "查询或操作失败，请稍后重试"})
		return
	}
	writeJSON(w, 200, map[string]any{"data": result})
}

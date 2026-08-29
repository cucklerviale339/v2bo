package httpapi

import (
	"net/http"
	"strconv"
	"strings"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/session"
)

func handleAdminSubscribeAccessStats(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	current, err := subscribeAccessPositiveInt(r.URL.Query().Get("current"), 1, 1_000_000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "页码无效"})
		return true
	}
	pageSize, err := subscribeAccessPositiveInt(r.URL.Query().Get("page_size"), 20, 100)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "每页数量无效（1-100）"})
		return true
	}
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	if len(keyword) > 255 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "查询内容过长"})
		return true
	}
	sort := strings.TrimSpace(r.URL.Query().Get("sort"))
	if sort != "" && sort != "count" && sort != "ip_count" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "排序方式无效"})
		return true
	}

	result, err := adminService.GetSubscribeAccessStats(r.Context(), admin.SubscribeAccessStatsRequest{
		Keyword: keyword, Current: current, PageSize: pageSize, Sort: sort,
	})
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
	return true
}

func handleAdminSubscribeAccessUserDetail(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	userID, err := subscribeAccessPositiveInt(r.URL.Query().Get("id"), 0, 2_147_483_647)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "用户 ID 无效"})
		return true
	}
	result, err := adminService.GetSubscribeAccessUserDetail(r.Context(), userID)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
	return true
}

func handleAdminSubscribeAccessUASearch(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	if keyword == "" || len(keyword) > 255 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "请输入有效的 UA 关键词"})
		return true
	}
	current, err := subscribeAccessPositiveInt(r.URL.Query().Get("current"), 1, 1_000_000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "页码无效"})
		return true
	}
	pageSize, err := subscribeAccessPositiveInt(r.URL.Query().Get("page_size"), 20, 100)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "每页数量无效（1-100）"})
		return true
	}
	result, err := adminService.SearchSubscribeAccessByUA(r.Context(), keyword, current, pageSize)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
	return true
}

func handleAdminSubscribeAccessRetention(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "请求参数无效"})
		return true
	}
	days, err := subscribeAccessPositiveInt(inputs["days"], 0, 3650)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "保留天数无效（1-3650 天）"})
		return true
	}
	ok, err := adminService.SetSubscribeAccessRetention(r.Context(), days)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": ok})
	return true
}

func handleAdminDailyLowTrafficUsers(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	current, err := subscribeAccessPositiveInt(r.URL.Query().Get("current"), 1, 1_000_000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "页码无效"})
		return true
	}
	pageSize, err := subscribeAccessPositiveInt(r.URL.Query().Get("page_size"), 20, 100)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "每页数量无效（1-100）"})
		return true
	}
	thresholdKB, err := subscribeAccessPositiveInt(r.URL.Query().Get("threshold_kb"), 200, 1_048_576)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "流量阈值无效（1-1048576 KB）"})
		return true
	}
	result, err := adminService.GetDailyLowTrafficUsers(r.Context(), current, pageSize, thresholdKB*1024)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
	return true
}

func handleAdminConsecutiveLowTrafficUsers(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	disableResponseCache(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	current, err := subscribeAccessPositiveInt(r.URL.Query().Get("current"), 1, 1_000_000)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "页码无效"})
		return true
	}
	pageSize, err := subscribeAccessPositiveInt(r.URL.Query().Get("page_size"), 20, 100)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "每页数量无效（1-100）"})
		return true
	}
	thresholdKB, err := subscribeAccessPositiveInt(r.URL.Query().Get("threshold_kb"), 200, 1_048_576)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "流量阈值无效（1-1048576 KB）"})
		return true
	}
	days, err := subscribeAccessPositiveInt(r.URL.Query().Get("days"), 3, 365)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "统计天数无效（1-365 天）"})
		return true
	}

	result, err := adminService.GetConsecutiveLowTrafficUsers(r.Context(), current, pageSize, thresholdKB*1024, days)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
	return true
}

func subscribeAccessPositiveInt(raw string, fallback, maximum int64) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 || value > maximum {
		return 0, strconv.ErrSyntax
	}
	return value, nil
}

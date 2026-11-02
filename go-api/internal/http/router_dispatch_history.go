package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"forest/go-api/internal/admin"
)

type dispatchHistoryService interface {
	ListDispatchHistory(context.Context, admin.DispatchHistoryRequest) (admin.DispatchHistoryResult, error)
}

// Called after administrator authentication; reads never launch checks or
// expire/delete history. Retention runs in a separate background worker.
func handleDispatchHistory(w http.ResponseWriter, r *http.Request, service admin.Service) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, 405, map[string]any{"message": "仅支持查询检测历史"})
		return
	}
	p, ok := service.(dispatchHistoryService)
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "检测历史服务暂不可用"})
		return
	}
	q := r.URL.Query()
	req := admin.DispatchHistoryRequest{Kind: q.Get("kind"), Source: q.Get("source"), Host: q.Get("host"), EventType: q.Get("event_type"), Page: 1}
	for _, v := range []struct {
		name   string
		target *int64
	}{{"page", &req.Page}, {"port", &req.Port}, {"probe_id", &req.ProbeID}, {"from", &req.From}, {"to", &req.To}} {
		if raw, exists := q[v.name]; exists {
			if len(raw) != 1 {
				writeJSON(w, 400, map[string]any{"message": "历史筛选参数无效"})
				return
			}
			n, err := strconv.ParseInt(raw[0], 10, 64)
			if err != nil || n < 0 || (v.name == "page" && n < 1) {
				writeJSON(w, 400, map[string]any{"message": "历史筛选参数无效"})
				return
			}
			*v.target = n
		}
	}
	if raw, exists := q["success"]; exists {
		if len(raw) != 1 || (raw[0] != "true" && raw[0] != "false") {
			writeJSON(w, 400, map[string]any{"message": "检测结果筛选无效"})
			return
		}
		value := raw[0] == "true"
		req.Success = &value
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	result, err := p.ListDispatchHistory(ctx, req)
	if err != nil {
		code := 500
		message := "检测历史读取失败，请检查服务日志"
		if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
			code = 400
			message = "历史筛选参数无效"
		}
		writeJSON(w, code, map[string]any{"message": message})
		return
	}
	writeJSON(w, 200, result)
}

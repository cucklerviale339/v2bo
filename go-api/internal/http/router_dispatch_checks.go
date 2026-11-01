package httpapi

import (
	"context"
	"errors"
	"forest/go-api/internal/admin"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type dispatchCheckService interface {
	ListDispatchPool(context.Context) ([]admin.DispatchPoolItem, error)
	SaveDispatchPool(context.Context, []admin.DispatchPoolSave) ([]int64, error)
	RefreshDispatchPool(context.Context, []int64) error
	DeleteDispatchPool(context.Context, []int64) (int64, error)
	DeleteFaultyDispatchPool(context.Context, []int64) (admin.DispatchPoolDeleteResult, error)
	StartDispatchRun(context.Context, admin.DispatchRunRequest) (int64, error)
	ListDispatchRuns(context.Context, int) ([]admin.DispatchCheckRun, int64, error)
	DispatchRunResults(context.Context, int64, int) ([]admin.DispatchCheckResult, int64, error)
	ClearDispatchRuns(context.Context) (int64, error)
}

// This handler is reached only after administrator authentication.
func handleDispatchChecks(w http.ResponseWriter, r *http.Request, service admin.Service, path string) {
	p, ok := service.(dispatchCheckService)
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "检测服务暂不可用"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var data any
	var err error
	var total int64
	paginated := false
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil || page < 1 || page > 100000 {
			writeJSON(w, 400, map[string]any{"message": "页码无效"})
			return
		}
	}
	switch {
	case path == "dispatch-pool" && r.Method == http.MethodGet:
		data, err = p.ListDispatchPool(ctx)
	case path == "dispatch-pool" && r.Method == http.MethodPost:
		var req struct {
			Items []admin.DispatchPoolSave `json:"items"`
		}
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		data, err = p.SaveDispatchPool(ctx, req.Items)
	case (path == "dispatch-pool/refresh" || path == "dispatch-pool/delete" || path == "dispatch-pool/delete-faulty") && r.Method == http.MethodPost:
		var req struct {
			IDs []int64 `json:"ids"`
		}
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		if path == "dispatch-pool/refresh" {
			err = p.RefreshDispatchPool(ctx, req.IDs)
			data = true
		} else if path == "dispatch-pool/delete-faulty" {
			data, err = p.DeleteFaultyDispatchPool(ctx, req.IDs)
		} else {
			data, err = p.DeleteDispatchPool(ctx, req.IDs)
		}
	case path == "dispatch-runs" && r.Method == http.MethodGet:
		data, total, err = p.ListDispatchRuns(ctx, page)
		paginated = true
	case path == "dispatch-runs" && r.Method == http.MethodDelete:
		data, err = p.ClearDispatchRuns(ctx)
	case strings.HasPrefix(path, "dispatch-runs/") && r.Method == http.MethodGet:
		id, parseErr := strconv.ParseInt(strings.TrimPrefix(path, "dispatch-runs/"), 10, 64)
		if parseErr != nil || id <= 0 {
			writeJSON(w, 400, map[string]any{"message": "任务 ID 无效"})
			return
		}
		data, total, err = p.DispatchRunResults(ctx, id, page)
		paginated = true
	default:
		writeJSON(w, 405, map[string]any{"message": "不支持此请求"})
		return
	}
	if err != nil {
		if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
			writeJSON(w, 400, map[string]any{"message": err.Error()})
		} else {
			writeJSON(w, 500, map[string]any{"message": "检测操作失败，请刷新后重试"})
		}
		return
	}
	body := map[string]any{"data": data}
	if paginated {
		body["total"] = total
		body["page"] = page
	}
	writeJSON(w, 200, body)
}

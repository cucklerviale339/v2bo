package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"forest/go-api/internal/admin"
)

type dispatchAutoSplitService interface {
	GetDispatchAutoSplit(context.Context) (admin.DispatchAutoSplitView, error)
	SaveDispatchAutoSplit(context.Context, admin.DispatchAutoSplitSettings) error
}

func handleDispatchSplitGroupEdit(w http.ResponseWriter, r *http.Request, service admin.Service) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		writeJSON(w, 405, map[string]any{"message": "仅支持保存分组编辑"})
		return
	}
	s, ok := service.(interface {
		EditDispatchSplitGroups(context.Context, admin.DispatchSplitEditRequest) error
	})
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "分组编辑服务暂不可用"})
		return
	}
	var req admin.DispatchSplitEditRequest
	if !decodeStrictDNSFailoverJSON(w, r, &req) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.EditDispatchSplitGroups(ctx, req); err != nil {
		code, message := 500, "保存分组失败，请刷新后重试"
		if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
			code, message = 400, err.Error()
		}
		writeJSON(w, code, map[string]any{"message": message})
		return
	}
	writeJSON(w, 200, map[string]any{"data": true})
}

func handleDispatchAutoSplit(w http.ResponseWriter, r *http.Request, service admin.Service) {
	if r.Method != http.MethodGet && r.Method != http.MethodPut {
		w.Header().Set("Allow", "GET, PUT")
		writeJSON(w, 405, map[string]any{"message": "不支持此请求"})
		return
	}
	s, ok := service.(dispatchAutoSplitService)
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "自动二分服务暂不可用"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if r.Method == http.MethodPut {
		var req admin.DispatchAutoSplitSettings
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		if err := s.SaveDispatchAutoSplit(ctx, req); err != nil {
			code := 500
			message := "保存自动二分设置失败"
			if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
				code = 400
				message = err.Error()
			}
			writeJSON(w, code, map[string]any{"message": message})
			return
		}
	}
	view, err := s.GetDispatchAutoSplit(ctx)
	if err != nil {
		writeJSON(w, 500, map[string]any{"message": "自动二分设置读取失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"data": view})
}

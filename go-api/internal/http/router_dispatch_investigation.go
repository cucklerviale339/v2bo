package httpapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"forest/go-api/internal/admin"
)

type investigationService interface {
	GetInvestigation(context.Context, int64) (admin.InvestigationView, error)
	SaveInvestigation(context.Context, admin.InvestigationSettings) error
	EditInvestigation(context.Context, admin.InvestigationEdit) error
	ConfirmInvestigation(context.Context, admin.InvestigationAction) error
	TriggerInvestigation(context.Context, admin.InvestigationAction) error
}

func handleInvestigation(w http.ResponseWriter, r *http.Request, service admin.Service, path string) {
	edit := path == "dispatch-investigation/groups"
	action := path == "dispatch-investigation/confirm" || path == "dispatch-investigation/trigger"
	if (action && r.Method != http.MethodPost) || (edit && r.Method != http.MethodPut) || (!action && !edit && r.Method != http.MethodPut && r.Method != http.MethodGet) {
		if action {
			w.Header().Set("Allow", "POST")
		} else if edit {
			w.Header().Set("Allow", "PUT")
		} else {
			w.Header().Set("Allow", "GET, PUT")
		}
		writeJSON(w, 405, map[string]any{"message": "不支持此请求"})
		return
	}
	s, ok := service.(investigationService)
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "入口筛选服务暂不可用"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var err error
	if action {
		var req admin.InvestigationAction
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		if path == "dispatch-investigation/confirm" {
			err = s.ConfirmInvestigation(ctx, req)
		} else {
			err = s.TriggerInvestigation(ctx, req)
		}
	} else if edit {
		var req admin.InvestigationEdit
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		err = s.EditInvestigation(ctx, req)
	} else if r.Method == http.MethodPut {
		var req admin.InvestigationSettings
		if !decodeStrictDNSFailoverJSON(w, r, &req) {
			return
		}
		err = s.SaveInvestigation(ctx, req)
	}
	if err != nil {
		code := 500
		message := "保存失败，请刷新后重试"
		if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
			code = 400
			message = err.Error()
		} else if errors.Is(err, admin.ErrInvestigationBusy) {
			code = http.StatusConflict
			message = err.Error()
			w.Header().Set("Retry-After", "2")
		} else {
			log.Printf("Entry investigation request failed action=%s: %v", path, err)
			if errors.Is(err, context.DeadlineExceeded) {
				code = http.StatusGatewayTimeout
				message = "处理请求超时，请刷新分组状态后重试"
			}
		}
		writeJSON(w, code, map[string]any{"message": message})
		return
	}
	page := int64(1)
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || page < 1 || page > 100000 {
			writeJSON(w, 400, map[string]any{"message": "页码无效"})
			return
		}
	}
	view, err := s.GetInvestigation(ctx, page)
	if err != nil {
		writeJSON(w, 500, map[string]any{"message": "入口筛选数据读取失败"})
		return
	}
	writeJSON(w, 200, map[string]any{"data": view})
}

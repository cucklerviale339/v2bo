package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"forest/go-api/internal/admin"
)

type dispatchMonitorService interface {
	ListDispatchMonitors(context.Context) ([]admin.DispatchMonitor, error)
	SaveDispatchMonitor(context.Context, admin.DispatchMonitorSaveRequest) error
}

type dispatchMonitorDeleteService interface {
	ListDispatchMonitorsIncludingDeleted(context.Context) ([]admin.DispatchMonitor, error)
	DeleteDispatchMonitors(context.Context, []string) error
}

// Called only after the DNS admin route has authenticated an administrator.
func handleDNSDispatchEntries(w http.ResponseWriter, r *http.Request, service admin.Service) {
	provider, ok := service.(dispatchMonitorService)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "入口监控服务暂不可用"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	switch r.Method {
	case http.MethodGet:
		var entries []admin.DispatchMonitor
		var err error
		switch r.URL.Query().Get("include_deleted") {
		case "", "false", "0":
			entries, err = provider.ListDispatchMonitors(ctx)
		case "true", "1":
			deletedProvider, available := service.(dispatchMonitorDeleteService)
			if !available {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "已删除入口服务暂不可用"})
				return
			}
			entries, err = deletedProvider.ListDispatchMonitorsIncludingDeleted(ctx)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "include_deleted 参数无效"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "加载入口监控失败"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": entries, "calculated_at": time.Now().Unix()})
	case http.MethodPut:
		var request admin.DispatchMonitorSaveRequest
		if !decodeStrictDNSFailoverJSON(w, r, &request) {
			return
		}
		if err := provider.SaveDispatchMonitor(ctx, request); err != nil {
			if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
			} else {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "保存入口监控失败"})
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": true})
	default:
		dnsFailoverMethodNotAllowed(w, r, http.MethodGet+", "+http.MethodPut)
	}
}

func handleDNSDispatchEntriesDelete(w http.ResponseWriter, r *http.Request, service admin.Service) {
	if r.Method != http.MethodPost {
		dnsFailoverMethodNotAllowed(w, r, http.MethodPost)
		return
	}
	provider, ok := service.(dispatchMonitorDeleteService)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "入口删除服务暂不可用"})
		return
	}
	var request struct {
		Hosts []string `json:"hosts"`
	}
	if !decodeStrictDNSFailoverJSON(w, r, &request) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := provider.DeleteDispatchMonitors(ctx, request.Hosts); err != nil {
		if errors.Is(err, admin.ErrDNSProbeInvalidRequest) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "删除入口监控失败"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": true})
}

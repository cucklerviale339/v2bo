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
		entries, err := provider.ListDispatchMonitors(ctx)
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

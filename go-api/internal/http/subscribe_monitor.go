package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"forest/go-api/internal/subscribeguard"
)

type subscriptionMonitor interface {
	MonitoringStatus(context.Context) (subscribeguard.MonitorStatus, error)
	SetIPLookup(context.Context, bool, int64, int64) error
	RetryIPLookups(context.Context) (int64, error)
	RiskHistory(context.Context, subscribeguard.RiskHistoryFilter) (subscribeguard.RiskHistoryResult, error)
	ReviewRisk(context.Context, int64, int64, int64, string, string) error
}

func handleSubscriptionMonitor(w http.ResponseWriter, ctx context.Context, state *routerState, action string, inputs map[string]string, adminID int64) {
	monitor, ok := state.subscribeGuard.(subscriptionMonitor)
	if !ok {
		writeJSON(w, 503, map[string]any{"message": "风险监控未就绪"})
		return
	}
	invalid := func() { writeJSON(w, 400, map[string]any{"message": "监控参数无效"}) }
	var result any = true
	var err error
	switch action {
	case "monitor-status":
		result, err = monitor.MonitoringStatus(ctx)
	case "monitor-config":
		revision, parseErr := strconv.ParseInt(inputs["revision"], 10, 64)
		if parseErr != nil || revision < 0 || (inputs["enabled"] != "true" && inputs["enabled"] != "false") {
			invalid()
			return
		}
		err = monitor.SetIPLookup(ctx, inputs["enabled"] == "true", revision, adminID)
	case "monitor-retry":
		var count int64
		count, err = monitor.RetryIPLookups(ctx)
		result = map[string]any{"queued": count}
	case "risk-history":
		current, size := 1, 20
		for name, target := range map[string]*int{"current": &current, "page_size": &size} {
			if value := inputs[name]; value != "" {
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil {
					invalid()
					return
				}
				*target = parsed
			}
		}
		status := inputs["status"]
		if current < 1 || current > 100000 || size < 1 || size > 100 || (status != "" && status != "pending" && status != "handled" && status != "false_positive" && status != "suppressed") {
			invalid()
			return
		}
		result, err = monitor.RiskHistory(ctx, subscribeguard.RiskHistoryFilter{Keyword: inputs["keyword"], Status: status, Current: current, PageSize: size})
	case "risk-review":
		id, idErr := strconv.ParseInt(inputs["id"], 10, 64)
		revision, revisionErr := strconv.ParseInt(inputs["revision"], 10, 64)
		status, note := inputs["status"], strings.TrimSpace(inputs["note"])
		if idErr != nil || revisionErr != nil || id <= 0 || revision < 0 || note == "" || len([]rune(note)) > 500 || (status != "handled" && status != "false_positive") {
			invalid()
			return
		}
		err = monitor.ReviewRisk(ctx, id, revision, adminID, status, note)
	}
	if errors.Is(err, subscribeguard.ErrConflict) {
		writeJSON(w, 409, map[string]any{"message": "记录已被更新，请刷新后重试"})
	} else if err != nil {
		writeJSON(w, 503, map[string]any{"message": "风险历史或 IP 情报暂不可用，原订阅防护仍可用"})
	} else {
		writeJSON(w, 200, map[string]any{"data": result})
	}
}

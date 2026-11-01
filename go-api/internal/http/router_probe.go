package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
)

type dispatchProbeService interface {
	ListDispatchProbeTasks(context.Context, int64) ([]admin.DNSProbeTask, error)
	ReportDispatchProbeResults(context.Context, int64, admin.DNSProbeResultsRequest) (admin.DNSProbeReportResult, error)
}

type dispatchCheckProbeService interface {
	ListDispatchCheckTasks(context.Context, int64) ([]admin.DNSProbeTask, error)
	ReportDispatchCheckResults(context.Context, int64, admin.DNSProbeResultsRequest) (admin.DNSProbeReportResult, error)
}

const (
	maxDNSProbeBearerSecretBytes = 512
	maxDNSProbeHeartbeatBody     = 4 << 10
	maxDNSProbeResultsBody       = 1 << 20
	maxDNSProbeResultsBatch      = 500
)

func WithDNSProbeService(service admin.DNSProbeService) Option {
	return func(state *routerState) {
		state.dnsProbe = service
	}
}

type probeRequestIPResolver struct {
	trusted []netip.Prefix
}

func handleDNSProbeHeartbeat(w http.ResponseWriter, r *http.Request, service admin.DNSProbeService, resolver probeRequestIPResolver) {
	if !requireDNSProbeMethod(w, r, http.MethodPost) {
		return
	}
	identity, ok := authenticateDNSProbeRequest(w, r, service)
	if !ok {
		return
	}
	if !requireDNSProbeJSONContentType(w, r) {
		return
	}
	var request admin.DNSProbeHeartbeatRequest
	if err := decodeDNSProbeJSON(w, r, maxDNSProbeHeartbeatBody, &request); err != nil {
		writeDNSProbeDecodeError(w, err)
		return
	}
	request.PublicIP = resolver.Resolve(r)
	if request.PublicIP == "" {
		writeDNSProbeBadRequest(w)
		return
	}
	result, err := service.HeartbeatDNSProbe(r.Context(), identity.ID, request)
	if err != nil {
		writeDNSProbeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func handleDNSProbeTasks(w http.ResponseWriter, r *http.Request, service admin.DNSProbeService) {
	if !requireDNSProbeMethod(w, r, http.MethodGet) {
		return
	}
	identity, ok := authenticateDNSProbeRequest(w, r, service)
	if !ok {
		return
	}
	tasks, err := service.ListDNSProbeTasks(r.Context(), identity.ID)
	if err != nil {
		writeDNSProbeServiceError(w, err)
		return
	}
	if tasks == nil {
		tasks = make([]admin.DNSProbeTask, 0)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": tasks, "monitor_transport": true})
}

// Auxiliary failures never prevent legacy DNS task delivery.
func handleDispatchProbeTasks(w http.ResponseWriter, r *http.Request, service admin.DNSProbeService) {
	if !requireDNSProbeMethod(w, r, http.MethodGet) {
		return
	}
	identity, ok := authenticateDNSProbeRequest(w, r, service)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	tasks := []admin.DNSProbeTask{}
	if monitor, ok := service.(dispatchProbeService); ok {
		entries, err := monitor.ListDispatchProbeTasks(ctx, identity.ID)
		if err != nil {
			writeDNSProbeServiceError(w, err)
			return
		}
		tasks = append(tasks, entries...)
	}
	if checks, ok := service.(dispatchCheckProbeService); ok {
		extra, err := checks.ListDispatchCheckTasks(ctx, identity.ID)
		if err != nil {
			writeDNSProbeServiceError(w, err)
			return
		}
		tasks = append(tasks, extra...)
	}

	if len(tasks) > 1000 {
		writeJSON(w, 409, map[string]any{"message": "每枚探针最多支持 1000 个新增监控目标，请减少目标或停用部分监控"})
		return
	}
	payload, err := json.Marshal(map[string]any{"data": tasks})
	if err != nil || len(payload) > 768<<10 {
		writeJSON(w, 409, map[string]any{"message": "新增监控任务超过响应容量"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func handleDNSProbeResults(w http.ResponseWriter, r *http.Request, service admin.DNSProbeService) {
	if !requireDNSProbeMethod(w, r, http.MethodPost) {
		return
	}
	identity, ok := authenticateDNSProbeRequest(w, r, service)
	if !ok {
		return
	}
	if !requireDNSProbeJSONContentType(w, r) {
		return
	}
	var request admin.DNSProbeResultsRequest
	if err := decodeDNSProbeJSON(w, r, maxDNSProbeResultsBody, &request); err != nil {
		writeDNSProbeDecodeError(w, err)
		return
	}
	if request.Results == nil || len(request.Results) > maxDNSProbeResultsBatch {
		writeDNSProbeBadRequest(w)
		return
	}
	if r.URL.Path == "/api/v1/probe/monitor-results" && len(request.Results) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"data": admin.DNSProbeReportResult{GroupIDs: []int64{}}})
		return
	}
	legacy, dispatch := admin.DNSProbeResultsRequest{Results: []admin.DNSProbeResult{}}, admin.DNSProbeResultsRequest{Results: []admin.DNSProbeResult{}}
	checks := admin.DNSProbeResultsRequest{Results: []admin.DNSProbeResult{}}
	for _, result := range request.Results {
		if result.TargetID <= -(1 << 60) {
			checks.Results = append(checks.Results, result)
		} else if result.TargetID < 0 {
			dispatch.Results = append(dispatch.Results, result)
		} else {
			legacy.Results = append(legacy.Results, result)
		}
	}
	result := admin.DNSProbeReportResult{GroupIDs: []int64{}}
	var err error
	if r.URL.Path == "/api/v1/probe/monitor-results" && len(legacy.Results) > 0 {
		writeDNSProbeBadRequest(w)
		return
	}
	if len(legacy.Results) > 0 || (len(dispatch.Results) == 0 && len(checks.Results) == 0) {
		result, err = service.ReportDNSProbeResults(r.Context(), identity.ID, legacy)
		if err != nil {
			writeDNSProbeServiceError(w, err)
			return
		}
	}
	// A legacy endpoint never depends on auxiliary writes. Previous mixed batches
	// are acknowledged as skipped for negatives; new agents use monitor-results.
	if r.URL.Path != "/api/v1/probe/monitor-results" {
		result.Skipped += len(dispatch.Results) + len(checks.Results)
		writeJSON(w, http.StatusOK, map[string]any{"data": result})
		return
	}
	if len(legacy.Results) > 0 {
		writeDNSProbeBadRequest(w)
		return
	}
	if len(checks.Results) > 0 {
		provider, ok := service.(dispatchCheckProbeService)
		if !ok {
			writeDNSProbeBadRequest(w)
			return
		}
		result, err = provider.ReportDispatchCheckResults(r.Context(), identity.ID, checks)
		if err != nil {
			writeDNSProbeServiceError(w, err)
			return
		}
	}
	if len(dispatch.Results) > 0 {
		monitor, ok := service.(dispatchProbeService)
		if !ok {
			writeDNSProbeBadRequest(w)
			return
		}
		var extra admin.DNSProbeReportResult
		extra, err = monitor.ReportDispatchProbeResults(r.Context(), identity.ID, dispatch)
		result.Accepted += extra.Accepted
		result.Duplicates += extra.Duplicates
		result.Skipped += extra.Skipped
		if err != nil {
			writeDNSProbeServiceError(w, err)
			return
		}
	}
	if err != nil {
		writeDNSProbeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func requireDNSProbeMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "method not allowed"})
	return false
}

func authenticateDNSProbeRequest(w http.ResponseWriter, r *http.Request, service admin.DNSProbeService) (admin.DNSProbeIdentity, bool) {
	if service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "probe service unavailable"})
		return admin.DNSProbeIdentity{}, false
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		writeDNSProbeUnauthorized(w)
		return admin.DNSProbeIdentity{}, false
	}
	value := values[0]
	if !strings.HasPrefix(value, "Bearer ") {
		writeDNSProbeUnauthorized(w)
		return admin.DNSProbeIdentity{}, false
	}
	secret := strings.TrimPrefix(value, "Bearer ")
	if secret == "" || len(secret) > maxDNSProbeBearerSecretBytes || strings.IndexFunc(secret, func(character rune) bool {
		return character <= ' ' || character == '\u007f'
	}) >= 0 {
		writeDNSProbeUnauthorized(w)
		return admin.DNSProbeIdentity{}, false
	}
	identity, err := service.AuthenticateDNSProbe(r.Context(), secret)
	if err != nil {
		if errors.Is(err, admin.ErrDNSProbeUnauthorized) {
			writeDNSProbeUnauthorized(w)
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "probe service unavailable"})
		}
		return admin.DNSProbeIdentity{}, false
	}
	return identity, true
}

func decodeDNSProbeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, target any) error {
	if r.Body == nil {
		return io.EOF
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func writeDNSProbeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "unauthorized"})
}

func requireDNSProbeJSONContentType(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"message": "Content-Type 必须是 application/json"})
		return false
	}
	return true
}

func writeDNSProbeDecodeError(w http.ResponseWriter, err error) {
	var maxBytesError *http.MaxBytesError
	if errors.As(err, &maxBytesError) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"message": "探针请求体过大"})
		return
	}
	writeDNSProbeBadRequest(w)
}

func writeDNSProbeBadRequest(w http.ResponseWriter) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid probe request"})
}

func writeDNSProbeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, admin.ErrDNSProbeUnauthorized):
		writeDNSProbeUnauthorized(w)
	case errors.Is(err, admin.ErrDNSProbeHeartbeatRequired):
		writeJSON(w, http.StatusConflict, map[string]any{"message": "探针需要先发送心跳"})
	case errors.Is(err, admin.ErrDNSProbeInvalidRequest):
		writeDNSProbeBadRequest(w)
	case errors.Is(err, admin.ErrUnavailable):
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "probe service unavailable"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]any{"message": "probe request failed"})
	}
}

func newProbeRequestIPResolver(values []string) probeRequestIPResolver {
	if values == nil {
		values = config.DefaultProbeTrustedProxyCIDRs()
	}
	resolver := probeRequestIPResolver{trusted: make([]netip.Prefix, 0, len(values))}
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			continue
		}
		resolver.trusted = append(resolver.trusted, prefix.Masked())
	}
	return resolver
}

// Resolve trusts Cloudflare/XFF/X-Real-IP only when the socket peer belongs to
// an explicitly configured proxy prefix. XFF contributes only its first item.
func (resolver probeRequestIPResolver) Resolve(r *http.Request) string {
	if r == nil {
		return ""
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	peerText := canonicalDNSProbeIP(remote)
	if peerText == "" {
		return ""
	}
	peer, _ := netip.ParseAddr(peerText)
	trustedPeer := false
	for _, prefix := range resolver.trusted {
		if prefix.Contains(peer) {
			trustedPeer = true
			break
		}
	}
	if !trustedPeer {
		return peerText
	}
	if ip := canonicalDNSProbeIP(r.Header.Get("CF-Connecting-IP")); ip != "" {
		return ip
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		if ip := canonicalDNSProbeIP(strings.SplitN(forwarded, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if ip := canonicalDNSProbeIP(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	return peerText
}

func canonicalDNSProbeIP(value string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" {
		return ""
	}
	return addr.Unmap().String()
}

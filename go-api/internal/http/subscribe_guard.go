package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"forest/go-api/internal/config"
	"forest/go-api/internal/subscribeguard"
)

type subscriptionGuardStore interface {
	Policy(context.Context) (subscribeguard.Policy, error)
	Save(context.Context, subscribeguard.Policy, int64) (subscribeguard.Policy, error)
	Rate(context.Context, string, int64) (bool, error)
	Record(subscribeguard.Event)
	Events(context.Context, subscribeguard.Filter) (map[string]any, error)
	Audit(context.Context) ([]map[string]any, error)
}

func WithSubscribeGuard(store subscriptionGuardStore) Option {
	return func(state *routerState) { state.subscribeGuard = store }
}

type subscriptionGuardKey struct{}

type subscriptionGuardRequest struct {
	policy subscribeguard.Policy
	event  subscribeguard.Event
}

type subscriptionGuardWriter struct {
	http.ResponseWriter
	status int
}

func (writer *subscriptionGuardWriter) WriteHeader(status int) {
	if writer.status == 0 {
		writer.status = status
		writer.ResponseWriter.WriteHeader(status)
	}
}

func (writer *subscriptionGuardWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *subscriptionGuardWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }

var subscriptionGuardErrorAt atomic.Int64

func subscriptionGuardError() {
	now := time.Now().Unix()
	previous := subscriptionGuardErrorAt.Load()
	if now-previous >= 60 && subscriptionGuardErrorAt.CompareAndSwap(previous, now) {
		log.Print("subscribe guard unavailable; allowing subscriptions without enforcement")
	}
}

func subscriptionGuardEndpoint(cfg config.Config, path string) string {
	if isClientSubscribePath(cfg, path) {
		return "subscribe"
	}
	switch path {
	case "/api/v1/client/app/getConfig":
		return "app_config"
	case "/api/v1/client/forest/entry-provider":
		return "entry_provider"
	case "/api/v1/user/forest/runtime-profile":
		return "runtime_profile"
	case "/api/v1/user/server/fetch":
		return "user_servers"
	}
	return ""
}

func beginSubscribeGuard(w http.ResponseWriter, r *http.Request, cfg config.Config, services *routerState) (http.ResponseWriter, *http.Request, func(), bool) {
	store := services.subscribeGuard
	noop := func() {}
	endpoint := subscriptionGuardEndpoint(cfg, r.URL.Path)
	if endpoint == "" || store == nil || os.Getenv("SUBSCRIBE_GUARD_FORCE_OFF") == "1" {
		return w, r, noop, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
	policy, err := store.Policy(ctx)
	cancel()
	if err != nil {
		subscriptionGuardError()
		return w, r, noop, false
	}
	if endpoint == "subscribe" {
		r = withClientSubscribePathToken(cfg, r)
		r = withRecoveredClientSubscribeQuery(r)
	}
	state := &subscriptionGuardRequest{policy: policy, event: subscribeguard.Event{
		IP: subscribeguard.ClientIP(r, policy.TrustedProxies), UA: subscribeguard.CleanUA(r.UserAgent()),
		Endpoint: endpoint, Mode: policy.Mode, Time: time.Now().Unix(),
		CrawlerUA: subscribeguard.IsCrawlerUA(r.UserAgent()),
	}}
	state.event.UAWhitelisted = policy.Match("ua_allow", r.UserAgent(), time.Now()) || policy.Match("ip_allow", state.event.IP, time.Now())
	var requestToken string
	if endpoint != "runtime_profile" && endpoint != "user_servers" {
		if policy.Mode != "off" {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		token, tokenErr := readInputValue(r, "token")
		if tokenErr == nil {
			requestToken = token
			state.event.TokenHash = subscribeguard.Fingerprint(cfg.AppKey, token)
		}
	}
	r = r.WithContext(context.WithValue(r.Context(), subscriptionGuardKey{}, state))
	writer := &subscriptionGuardWriter{ResponseWriter: w}
	finish := func() {
		recovered := recover()
		if state.event.Blocked && state.event.UserID == 0 {
			lookupCtx, lookupCancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
			if resolver, ok := services.user.(interface {
				PeekClientUserID(context.Context, string) (int64, error)
			}); ok && requestToken != "" {
				if userID, err := resolver.PeekClientUserID(lookupCtx, requestToken); err == nil {
					state.event.UserID = userID
				}
			} else if (endpoint == "user_servers" || endpoint == "runtime_profile") && services.session != nil {
				if auth, err := readAuthToken(r); err == nil {
					if identity, err := services.session.Authenticate(lookupCtx, auth, false); err == nil && identity != nil {
						state.event.UserID = identity.ID
					}
				}
			}
			lookupCancel()
		}
		state.event.Status = writer.status
		if state.event.Status == 0 {
			state.event.Status = http.StatusOK
			if recovered != nil {
				state.event.Status = http.StatusInternalServerError
			}
		}
		store.Record(state.event)
		if recovered != nil {
			panic(recovered)
		}
	}
	if policy.Mode == "off" {
		return writer, r, finish, false
	}
	now := time.Now()
	state.event.Reason = policy.Reason(state.event.IP, state.event.TokenHash, r.UserAgent(), now)
	if state.event.Reason == "" {
		rateCtx, rateCancel := context.WithTimeout(r.Context(), 200*time.Millisecond)
		defer rateCancel()
		checks := []struct {
			key   string
			limit int64
			name  string
		}{}
		if policy.IPLimit > 0 && state.event.IP != "" && !policy.Match("ip_allow", state.event.IP, now) {
			checks = append(checks, struct {
				key   string
				limit int64
				name  string
			}{"ip:" + state.event.IP, policy.IPLimit, "ip_rate"})
		}
		if policy.TokenLimit > 0 && state.event.TokenHash != "" {
			checks = append(checks, struct {
				key   string
				limit int64
				name  string
			}{"token:" + state.event.TokenHash, policy.TokenLimit, "token_rate"})
		}
		for _, check := range checks {
			bucket := subscribeguard.Fingerprint(cfg.AppKey, strconv.FormatInt(policy.Revision, 10)+":"+check.key)
			allowed, rateErr := store.Rate(rateCtx, bucket, check.limit)
			if rateErr != nil {
				subscriptionGuardError()
				state.event.Reason = "guard_unavailable"
				return writer, r, finish, false
			}
			if !allowed {
				state.event.Reason = check.name
				break
			}
		}
	}
	if state.event.Reason != "" && policy.Mode == "enforce" {
		blockSubscribeGuard(writer, state)
		return writer, r, finish, true
	}
	return writer, r, finish, false
}

func blockSubscribeGuard(w http.ResponseWriter, state *subscriptionGuardRequest) {
	state.event.Blocked = true
	disableResponseCache(w)
	w.Header().Set("X-Subscribe-Guard", state.event.Reason)
	status := http.StatusForbidden
	if state.event.Reason == "ip_rate" || state.event.Reason == "token_rate" {
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", strconv.FormatInt(60-time.Now().Unix()%60, 10))
	}
	writePlainText(w, status, "Subscription request denied")
}

func subscribeGuardAuthenticated(w http.ResponseWriter, r *http.Request, userID int64) bool {
	state, ok := r.Context().Value(subscriptionGuardKey{}).(*subscriptionGuardRequest)
	if !ok {
		return true
	}
	state.event.UserID = userID
	if state.policy.Mode != "off" && state.policy.Match("user_block", strconv.FormatInt(userID, 10), time.Now()) {
		state.event.Reason = "user"
		if state.policy.Mode == "enforce" {
			blockSubscribeGuard(w, state)
			return false
		}
	}
	return true
}

func handleAdminSubscribeGuard(w http.ResponseWriter, r *http.Request, state *routerState, cfg config.Config, action string) {
	if action != "config" && action != "events" && action != "audit" {
		handleSubscribeGuardDashboard(w, r, state, action)
		return
	}
	disableResponseCache(w)
	r.Body = http.MaxBytesReader(w, r.Body, 512<<10)
	if r.Method != http.MethodGet && !(action == "config" && r.Method == http.MethodPost) {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return
	}
	identity, ok := authenticateRequest(w, r, state.session, true)
	if !ok {
		return
	}
	if state.subscribeGuard == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "订阅防护未就绪，请检查服务日志"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var result any
	var err error
	switch action {
	case "config":
		if r.Method == http.MethodGet {
			var policy subscribeguard.Policy
			policy, err = state.subscribeGuard.Policy(ctx)
			result = map[string]any{"policy": policy, "force_off": os.Getenv("SUBSCRIBE_GUARD_FORCE_OFF") == "1"}
		} else {
			var input struct {
				Policy subscribeguard.Policy `json:"policy"`
				Auth   string                `json:"auth_data"`
			}
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			decodeErr := decoder.Decode(&input)
			var extra any
			if decodeErr != nil || decoder.Decode(&extra) != io.EOF {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": "配置格式无效"})
				return
			}
			if err := input.Policy.Validate(cfg.AppKey); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
				return
			}
			result, err = state.subscribeGuard.Save(ctx, input.Policy, identity.ID)
		}
	case "events":
		keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
		outcome := r.URL.Query().Get("outcome")
		before := int64(0)
		userID := int64(0)
		if raw := r.URL.Query().Get("user_id"); raw != "" {
			userID, err = strconv.ParseInt(raw, 10, 64)
			if err != nil || userID <= 0 {
				writeJSON(w, http.StatusBadRequest, map[string]any{"message": "用户 ID 无效"})
				return
			}
		}
		ua := strings.TrimSpace(r.URL.Query().Get("ua"))
		crawlerOnly := r.URL.Query().Get("crawler_only")
		if crawlerOnly != "" && crawlerOnly != "0" && crawlerOnly != "1" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "查询参数无效"})
			return
		}
		if raw := r.URL.Query().Get("before"); raw != "" {
			before, err = strconv.ParseInt(raw, 10, 64)
		}
		if err != nil || before < 0 || len(keyword) > 255 || len(ua) > 255 || (outcome != "" && outcome != "allowed" && outcome != "blocked" && outcome != "matched" && outcome != "failed") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "查询参数无效"})
			return
		}
		result, err = state.subscribeGuard.Events(ctx, subscribeguard.Filter{Keyword: keyword, Outcome: outcome, Before: before, Limit: 50, UserID: userID, UA: ua, CrawlerOnly: crawlerOnly == "1"})
	case "audit":
		result, err = state.subscribeGuard.Audit(ctx)
	default:
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, subscribeguard.ErrConflict) {
		writeJSON(w, http.StatusConflict, map[string]any{"message": err.Error()})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "订阅防护读写失败，请稍后重试"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

package httpapi

import (
	"context"
	"forest/go-api/internal/session"
	"mime"
	"net/http"
	"strings"
)

type freshSessionService interface {
	AuthenticateFresh(context.Context, string, bool) (*session.Identity, error)
}

func authenticateSupportSession(w http.ResponseWriter, r *http.Request, sessions session.Service, requireAdmin bool) (*session.Identity, bool) {
	if sessions == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "session service unavailable"})
		return nil, false
	}
	// Never parse a write payload as auth input before strict decoding.
	token := strings.TrimSpace(r.Header.Get("Authorization"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("auth_data"))
	}
	if token == "" {
		handleSessionError(w, session.ErrUnauthorized)
		return nil, false
	}
	return authenticateSupportToken(w, r, sessions, token, requireAdmin)
}

func authenticateSupportToken(w http.ResponseWriter, r *http.Request, sessions session.Service, token string, requireAdmin bool) (*session.Identity, bool) {
	var identity *session.Identity
	var err error
	if fresh, ok := sessions.(freshSessionService); ok {
		identity, err = fresh.AuthenticateFresh(r.Context(), token, requireAdmin)
	} else {
		identity, err = sessions.Authenticate(r.Context(), token, requireAdmin)
	}
	if err != nil {
		handleSessionError(w, err)
		return nil, false
	}
	if identity == nil || (requireAdmin && identity.IsAdmin == 0) {
		handleSessionError(w, session.ErrUnauthorized)
		return nil, false
	}
	return identity, true
}

func decodeSupportJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeJSON(w, 415, map[string]any{"message": "Content-Type must be application/json"})
		return false
	}
	if err := decodeDNSProbeJSON(w, r, 32<<10, target); err != nil {
		writeJSON(w, 400, map[string]any{"message": "请求格式无效，仅接受声明字段的 JSON 对象"})
		return false
	}
	return true
}

package user

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"forest/go-api/internal/platform/postgres"
)

func (s *DBService) RecordSubscribeAccess(ctx context.Context, userID int64, clientIP, userAgent string) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	if userID <= 0 {
		return nil
	}
	s.subscribeAccessOnce.Do(func() {
		s.subscribeAccessErr = postgres.EnsureSubscribeAccessSchema(ctx, s.db)
	})
	if s.subscribeAccessErr != nil {
		return s.subscribeAccessErr
	}
	clientIP = normalizeSubscribeAccessIP(clientIP)
	userAgent = truncateSubscribeAccessValue(userAgent, 2048)
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO v2_subscribe_access_log (user_id, client_ip, user_agent, accessed_at, created_at)
VALUES ($1, $2, $3, $4, $4)`, userID, clientIP, userAgent, now)
	if err != nil {
		return fmt.Errorf("record subscribe access: %w", err)
	}
	s.cleanupSubscribeAccess(ctx, now)
	return nil
}

func normalizeSubscribeAccessIP(value string) string {
	value = strings.TrimSpace(strings.Split(value, ",")[0])
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	if parsed := net.ParseIP(value); parsed != nil {
		return parsed.String()
	}
	return ""
}

func truncateSubscribeAccessValue(value string, maxBytes int) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (s *DBService) cleanupSubscribeAccess(ctx context.Context, now int64) {
	s.subscribeCleanupMu.Lock()
	defer s.subscribeCleanupMu.Unlock()
	if now-s.subscribeCleanupAt < 3600 {
		return
	}
	s.subscribeCleanupAt = now
	var days int64
	if err := s.db.QueryRowContext(ctx, `SELECT log_keep_days FROM v2_subscribe_access_config WHERE id = 1`).Scan(&days); err != nil || days <= 0 {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM v2_subscribe_access_log WHERE accessed_at < $1`, now-days*86400)
}

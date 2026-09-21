package user

import (
	"context"
	"strings"
)

func (s *DBService) PeekClientUserID(ctx context.Context, token string) (int64, error) {
	if s.db == nil {
		return 0, ErrUnavailable
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return 0, ErrClientTokenInvalid
	}
	switch s.currentConfig().ShowSubscribeMethod {
	case 1:
		canonicalToken, ok, err := s.kvGet(ctx, "otpn_"+token)
		if err != nil {
			return 0, err
		}
		canonicalToken = strings.TrimSpace(canonicalToken)
		if !ok || canonicalToken == "" {
			return 0, ErrClientTokenInvalid
		}
		return s.findUserIDByToken(ctx, canonicalToken)
	case 2:
		canonicalToken, ok, err := s.kvGet(ctx, "totp_"+token)
		if err != nil {
			return 0, err
		}
		canonicalToken = strings.TrimSpace(canonicalToken)
		if ok && canonicalToken != "" {
			return s.findUserIDByToken(ctx, canonicalToken)
		}
		userID, _, err := s.resolveTimedClientToken(ctx, token)
		return userID, err
	default:
		return s.findUserIDByToken(ctx, token)
	}
}

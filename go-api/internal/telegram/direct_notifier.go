package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrDirectNotifierUnavailable = errors.New("telegram direct notifier unavailable")

type DirectNotifier struct {
	service *Service
}

func (s *Service) DirectNotifier() *DirectNotifier {
	return &DirectNotifier{service: s}
}

func (n *DirectNotifier) NotifyAdmins(ctx context.Context, message string, includeStaff bool) error {
	if n == nil || n.service == nil {
		return ErrDirectNotifierUnavailable
	}
	service := n.service
	cfg := service.currentConfig()
	if !cfg.TelegramBotEnable || strings.TrimSpace(cfg.TelegramBotToken) == "" || service.resolveRecipients == nil || service.sendMessage == nil {
		return ErrDirectNotifierUnavailable
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return nil
	}
	chatIDs, err := service.resolveRecipients(ctx, includeStaff)
	if err != nil {
		return err
	}
	seen := make(map[int64]bool)
	var failures []error
	for _, chatID := range chatIDs {
		if chatID == 0 || seen[chatID] {
			continue
		}
		seen[chatID] = true
		remaining := []rune(message)
		for len(remaining) > 0 {
			length := min(len(remaining), 2000)
			if err := service.sendMessage(ctx, chatID, string(remaining[:length])); err != nil {
				failures = append(failures, fmt.Errorf("send DNS notification to %d: %w", chatID, err))
				break
			}
			remaining = remaining[length:]
		}
	}
	if len(seen) == 0 {
		return ErrDirectNotifierUnavailable
	}
	return errors.Join(failures...)
}

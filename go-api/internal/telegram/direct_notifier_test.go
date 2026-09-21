package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"

	"forest/go-api/internal/config"
)

func TestDNSDirectNotifierReturnsDeliveryFailuresWithoutQueueing(t *testing.T) {
	jobs := &captureTelegramQueue{}
	service := NewService(config.Config{TelegramBotEnable: true, TelegramBotToken: "test"}, nil).WithQueueRuntime(jobs)
	service.resolveRecipients = func(context.Context, bool) ([]int64, error) { return []int64{0, 11, 11, 22}, nil }
	deliveryError := errors.New("delivery failed")
	var recipients []int64
	service.sendMessage = func(_ context.Context, chatID int64, text string) error {
		recipients = append(recipients, chatID)
		if chatID == 11 {
			return deliveryError
		}
		return nil
	}
	err := service.DirectNotifier().NotifyAdmins(context.Background(), "DNS failover", false)
	if !errors.Is(err, deliveryError) || len(jobs.queueNames) != 0 || len(recipients) != 2 {
		t.Fatalf("delivery must be synchronous, deduplicated and report failures: %v, %v, %v", err, jobs.queueNames, recipients)
	}
}

func TestDNSDirectNotifierRequiresConfiguredRecipients(t *testing.T) {
	for _, cfg := range []config.Config{{}, {TelegramBotEnable: true, TelegramBotToken: "test"}} {
		service := NewService(cfg, nil)
		if err := service.DirectNotifier().NotifyAdmins(context.Background(), "DNS failover", false); !errors.Is(err, ErrDirectNotifierUnavailable) {
			t.Fatalf("unavailable delivery must remain retryable: %v", err)
		}
	}
}

func TestDNSDirectNotifierSplitsUnicodeWithoutLosingText(t *testing.T) {
	service := NewService(config.Config{TelegramBotEnable: true, TelegramBotToken: "test"}, nil)
	service.resolveRecipients = func(context.Context, bool) ([]int64, error) { return []int64{11}, nil }
	var received strings.Builder
	service.sendMessage = func(_ context.Context, chatID int64, text string) error {
		if len([]rune(text)) > 2000 {
			t.Fatal("message exceeds safe Telegram chunk length")
		}
		received.WriteString(text)
		return nil
	}
	message := strings.Repeat("线路🌏", 2100)
	if err := service.DirectNotifier().NotifyAdmins(context.Background(), message, false); err != nil || received.String() != message {
		t.Fatalf("chunked notification lost content: %v", err)
	}
}

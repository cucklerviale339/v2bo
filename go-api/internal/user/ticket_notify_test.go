package user

import (
	"context"
	"strings"
	"testing"

	"forest/go-api/internal/config"

	"github.com/DATA-DOG/go-sqlmock"
)

type captureTicketNotifier struct {
	messages     []string
	includeStaff []bool
}

func (c *captureTicketNotifier) NotifyAdmins(_ context.Context, message string, includeStaff bool) error {
	c.messages = append(c.messages, message)
	c.includeStaff = append(c.includeStaff, includeStaff)
	return nil
}

func TestNotifyTicketAdminsUsesTelegramNotifier(t *testing.T) {
	notifier := &captureTicketNotifier{}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT email FROM v2_user WHERE id = \$1 LIMIT 1`).
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"email"}).AddRow("user@example.com"))

	service := NewDBService(config.Config{}, db).WithAdminNotifier(notifier)

	if err := service.notifyTicketAdmins(context.Background(), ticketAdminNotification{
		TicketID: 9,
		UserID:   7,
		Subject:  "Need help",
		Message:  "hello world",
	}); err != nil {
		t.Fatalf("notify ticket admins: %v", err)
	}

	if len(notifier.messages) != 1 {
		t.Fatalf("expected one notification, got %#v", notifier.messages)
	}
	if len(notifier.includeStaff) != 1 || !notifier.includeStaff[0] {
		t.Fatalf("expected include staff notification, got %#v", notifier.includeStaff)
	}
	message := notifier.messages[0]
	if !strings.Contains(message, "工单提醒 #9") || !strings.Contains(message, "用户邮箱：user@example.com") || !strings.Contains(message, "Need help") {
		t.Fatalf("unexpected notification message: %q", message)
	}
	if strings.Contains(message, "用户ID") {
		t.Fatalf("expected user id to be hidden, got %q", message)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

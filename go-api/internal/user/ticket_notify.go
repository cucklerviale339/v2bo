package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type ticketAdminNotification struct {
	TicketID  int64
	UserID    int64
	UserEmail string
	Subject   string
	Message   string
}

func (s *DBService) notifyTicketAdmins(ctx context.Context, notice ticketAdminNotification) error {
	if s == nil || s.notifier == nil {
		return nil
	}

	builder := &strings.Builder{}
	fmt.Fprintf(builder, "工单提醒 #%d\n", notice.TicketID)
	fmt.Fprintf(builder, "用户邮箱：%s\n", s.ticketUserEmail(ctx, notice))
	if subject := strings.TrimSpace(notice.Subject); subject != "" {
		fmt.Fprintf(builder, "主题：%s\n", subject)
	}
	if message := strings.TrimSpace(notice.Message); message != "" {
		fmt.Fprintf(builder, "内容：\n%s", message)
	}
	return s.notifier.NotifyAdmins(ctx, builder.String(), true)
}

func (s *DBService) ticketUserEmail(ctx context.Context, notice ticketAdminNotification) string {
	if email := strings.TrimSpace(notice.UserEmail); email != "" {
		return email
	}
	if s == nil || s.db == nil || notice.UserID <= 0 {
		return "-"
	}

	var email string
	if err := s.db.QueryRowContext(ctx, `SELECT email FROM v2_user WHERE id = $1 LIMIT 1`, notice.UserID).Scan(&email); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "-"
		}
		return "-"
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return "-"
	}
	return email
}

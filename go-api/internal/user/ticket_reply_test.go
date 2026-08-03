package user

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestReplyTicketLocksTicketBeforeCheckingAutoCloseState(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := &DBService{db: db}
	mock.ExpectBegin()
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT status, subject FROM v2_ticket WHERE id = $1 AND user_id = $2 LIMIT 1 FOR UPDATE`)).
		WithArgs(int64(21), int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"status", "subject"}).AddRow(int64(0), "Need help"))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT user_id FROM v2_ticket_message WHERE ticket_id = $1 ORDER BY id DESC LIMIT 1`)).
		WithArgs(int64(21)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(int64(1)))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO v2_ticket_message (user_id, ticket_id, message, created_at, updated_at)
VALUES ($1, $2, $3, $4, $4)`)).
		WithArgs(int64(9), int64(21), "Thanks", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE v2_ticket SET reply_status = 0, updated_at = $2 WHERE id = $1`)).
		WithArgs(int64(21), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	replied, err := service.ReplyTicket(context.Background(), 9, 21, "Thanks")
	if err != nil {
		t.Fatalf("reply ticket: %v", err)
	}
	if !replied {
		t.Fatal("expected ticket reply to succeed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

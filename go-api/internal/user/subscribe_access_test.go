package user

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRecordSubscribeAccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_subscribe_access_log`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_subscribe_access_log_accessed_at`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_subscribe_access_log_user_at`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_subscribe_access_config`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO v2_subscribe_access_config`).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_subscribe_access_log`).
		WithArgs(int64(9), "203.0.113.7", "Clash/1.0", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(`SELECT log_keep_days FROM v2_subscribe_access_config`).
		WillReturnRows(sqlmock.NewRows([]string{"log_keep_days"}).AddRow(int64(7)))
	mock.ExpectExec(`DELETE FROM v2_subscribe_access_log`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	service := &DBService{db: db}
	if err := service.RecordSubscribeAccess(context.Background(), 9, " 203.0.113.7 ", " Clash/1.0 "); err != nil {
		t.Fatalf("record subscribe access: %v", err)
	}
	mock.ExpectExec(`INSERT INTO v2_subscribe_access_log`).
		WithArgs(int64(9), "203.0.113.8", "Clash/2.0", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(2, 1))
	if err := service.RecordSubscribeAccess(context.Background(), 9, "203.0.113.8", "Clash/2.0"); err != nil {
		t.Fatalf("record second subscribe access: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSubscribeAccessInputNormalization(t *testing.T) {
	if got := normalizeSubscribeAccessIP("203.0.113.7, 10.0.0.1"); got != "203.0.113.7" {
		t.Fatalf("normalized IP = %q", got)
	}
	if got := normalizeSubscribeAccessIP("not-an-ip"); got != "" {
		t.Fatalf("invalid IP should be empty, got %q", got)
	}
	if got := truncateSubscribeAccessValue(strings.Repeat("界", 1000), 2048); len(got) > 2048 || !strings.HasPrefix(got, "界") {
		t.Fatalf("invalid truncated UA: bytes=%d", len(got))
	}
}

package admin

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLookupUsersSearchesEmailAndPrioritizesExactMatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := &DBService{db: db}
	query := `SELECT id, email
FROM v2_user
WHERE email ILIKE $1
ORDER BY CASE WHEN LOWER(email) = LOWER($2) THEN 0 ELSE 1 END, id ASC
LIMIT $3`
	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs("%demo@example.com%", "demo@example.com", int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).
			AddRow(int64(9), "demo@example.com").
			AddRow(int64(12), "other-demo@example.com"))

	rows, err := service.LookupUsers(context.Background(), UserLookupRequest{Keyword: " demo@example.com "})
	if err != nil {
		t.Fatalf("lookup users: %v", err)
	}
	if len(rows) != 2 || rows[0].ID != 9 || rows[0].Email != "demo@example.com" {
		t.Fatalf("unexpected lookup rows: %#v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestLookupUsersHydratesDistinctIDs(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := &DBService{db: db}
	query := `SELECT id, email
FROM v2_user
WHERE id IN ($1,$2)
ORDER BY id ASC
LIMIT $3`
	mock.ExpectQuery(regexp.QuoteMeta(query)).
		WithArgs(int64(9), int64(12), int64(20)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email"}).
			AddRow(int64(9), "first@example.com").
			AddRow(int64(12), "second@example.com"))

	rows, err := service.LookupUsers(context.Background(), UserLookupRequest{IDs: []int64{9, 12, 9, 0}})
	if err != nil {
		t.Fatalf("lookup users: %v", err)
	}
	if len(rows) != 2 || rows[1].ID != 12 {
		t.Fatalf("unexpected lookup rows: %#v", rows)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

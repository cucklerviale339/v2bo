package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDNSRetentionDrainsBatchesAndPreservesPendingEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := &DBService{db: db, dnsFailoverSchemaOK: true}
	mock.ExpectExec(`(?s)WITH doomed AS.*FROM v2_dns_failover_log.*LIMIT \$2.*DELETE FROM v2_dns_failover_log`).WithArgs(sqlmock.AnyArg(), int64(5000)).WillReturnResult(sqlmock.NewResult(0, 5000))
	mock.ExpectExec(`(?s)WITH doomed AS.*FROM v2_dns_failover_log.*LIMIT \$2.*DELETE FROM v2_dns_failover_log`).WithArgs(sqlmock.AnyArg(), int64(5000)).WillReturnResult(sqlmock.NewResult(0, 20))
	mock.ExpectExec(`(?s)WITH doomed AS.*FROM v2_dns_probe_result_inbox.*LIMIT \$2.*DELETE FROM v2_dns_probe_result_inbox`).WithArgs(sqlmock.AnyArg(), int64(5000)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`(?s)WITH doomed AS.*FROM v2_dns_failover_event WHERE notified_at IS NOT NULL AND created_at < \$1.*LIMIT \$2.*DELETE FROM v2_dns_failover_event`).WithArgs(sqlmock.AnyArg(), int64(5000)).WillReturnResult(sqlmock.NewResult(0, 1))
	if err := service.cleanupDNSFailoverRetention(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRetentionStopsOnFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	failure := errors.New("database busy")
	mock.ExpectExec("cleanup").WithArgs(int64(100), int64(5000)).WillReturnError(failure)
	if err := deleteDNSFailoverRetentionRows(context.Background(), db, "cleanup", 100, 5000); !errors.Is(err, failure) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

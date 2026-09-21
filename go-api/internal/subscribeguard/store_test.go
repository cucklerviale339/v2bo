package subscribeguard

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestConfigurationFailureIsCachedAsOff(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, "key")
	mock.ExpectQuery("SELECT revision, policy").WillReturnError(errors.New("database unavailable"))
	policy, err := store.Policy(context.Background())
	if err == nil || policy.Mode != "off" {
		t.Fatal("database error did not fail open")
	}
	policy, err = store.Policy(context.Background())
	if err == nil || policy.Mode != "off" {
		t.Fatal("failure caused repeated synchronous database reads")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRecordQueueIsBoundedAndNonblocking(t *testing.T) {
	store := NewStore(nil, "key")
	for index := 0; index < 1100; index++ {
		store.Record(Event{})
	}
	if store.dropped.Load() != 76 {
		t.Fatalf("expected 76 dropped records, got %d", store.dropped.Load())
	}
}

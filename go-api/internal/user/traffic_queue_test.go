package user

import (
	"context"
	"testing"

	"forest/go-api/internal/config"
	"forest/go-api/internal/queue"
	"github.com/DATA-DOG/go-sqlmock"
)

func TestQueueTrafficReportEnqueuesTrafficAndStatJobs(t *testing.T) {
	service := NewDBService(config.Config{}, nil).WithQueueRuntime(&captureTrafficQueue{})

	err := service.QueueTrafficReport(context.Background(), TrafficReport{
		ServerID:   7,
		ServerType: "vmess",
		ServerRate: 1.5,
		Traffic: map[int64]TrafficUsage{
			11: {U: 10, D: 20},
			12: {U: 30, D: 40},
		},
	})
	if err != nil {
		t.Fatalf("queue traffic report: %v", err)
	}

	q := service.jobs.(*captureTrafficQueue)
	if len(q.queueNames) != 2 || q.queueNames[0] != "traffic_fetch" || q.queueNames[1] != "stat" {
		t.Fatalf("unexpected queue names: %#v", q.queueNames)
	}
}

func TestApplyTrafficFetchDoesNotRestoreTrafficCollectedBeforeReset(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{}, db)
	const collectedAt = int64(1_754_000_000_123)
	mock.ExpectExec(`(?s)UPDATE v2_user AS target.*COALESCE\(target.traffic_reset_at, 0\) < \$4`).
		WithArgs(int64(11), int64(10), int64(20), collectedAt, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = service.applyTrafficFetch(context.Background(), TrafficReport{
		ServerID:    7,
		ServerType:  "vmess",
		ServerRate:  1,
		CollectedAt: collectedAt,
		Traffic: map[int64]TrafficUsage{
			11: {U: 10, D: 20},
		},
	})
	if err != nil {
		t.Fatalf("apply traffic fetch: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

type captureTrafficQueue struct {
	queueNames []string
}

func (c *captureTrafficQueue) Enqueue(queueName, jobName string, fn queue.JobFunc) error {
	c.queueNames = append(c.queueNames, queueName)
	return nil
}

func (c *captureTrafficQueue) Snapshot() queue.Snapshot {
	return queue.Snapshot{}
}

package admin

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
	"github.com/DATA-DOG/go-sqlmock"
)

type testDispatchCatalog struct{ entries []usersvc.DispatchEntry }

func (c *testDispatchCatalog) DispatchEntries(context.Context) ([]usersvc.DispatchEntry, error) {
	return c.entries, nil
}

func newDispatchTestService(t *testing.T) (*DBService, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &DBService{db: db, dnsFailoverSchemaOK: true, dispatchSchemaOK: true, dispatchCatalog: &testDispatchCatalog{[]usersvc.DispatchEntry{{Host: "entry.example", UserIDs: []string{"42"}, UserIDRanges: []string{}, Sources: []string{"内鬼管理规则 #1"}}}}}, mock
}

func TestDispatchMonitorSaveCustomPortAndBindingValidation(t *testing.T) {
	s, mock := newDispatchTestService(t)
	req := DispatchMonitorSaveRequest{Host: "ENTRY.EXAMPLE.", CheckPort: 18443, Enabled: true, CheckIntervalSec: 10, TCPTimeoutMS: 500, ProbeIDs: []int64{7, 7}}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT enabled FROM v2_dns_probe WHERE id=\$1 FOR SHARE`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"enabled"}).AddRow(1))
	mock.ExpectQuery(`INSERT INTO v2_dispatch_monitor.*version=v2_dispatch_monitor.version\+1 RETURNING id`).WithArgs("entry.example", int64(18443), true, int64(10), int64(500)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(3))
	mock.ExpectExec(`DELETE FROM v2_dispatch_monitor_probe WHERE monitor_id=\$1`).WithArgs(int64(3)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_dispatch_monitor_probe`).WithArgs(int64(3), int64(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT \(SELECT count`).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectCommit()
	if err := s.SaveDispatchMonitor(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Host = "removed.example"
	if err := s.SaveDispatchMonitor(context.Background(), req); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal(err)
	}
	req.Host = "entry.example"
	req.ProbeIDs = nil
	if err := s.SaveDispatchMonitor(context.Background(), req); !errors.Is(err, ErrDNSProbeInvalidRequest) {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchTasksExcludeRemovedHostsAndUseSeparateNamespace(t *testing.T) {
	s, mock := newDispatchTestService(t)
	mock.ExpectQuery(`SELECT m.id,m.host,m.check_port`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"id", "host", "port", "interval", "timeout", "version", "run"}).AddRow(3, "entry.example", 18443, 10, 500, 9, 4).AddRow(4, "removed.example", 443, 30, 3000, 1, 1))
	tasks, err := s.ListDispatchProbeTasks(context.Background(), 7)
	if err != nil || len(tasks) != 1 || tasks[0].TargetID != -3 || tasks[0].CheckPort != 18443 || tasks[0].TargetVersion != 9 {
		t.Fatalf("%#v %v", tasks, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchReportsRejectOldConfigAndDoNotEnqueueDNSChanges(t *testing.T) {
	s, mock := newDispatchTestService(t)
	success, latency := true, int64(12)
	request := DNSProbeResultsRequest{Results: []DNSProbeResult{
		{ResultID: "-3-100", TargetID: -3, TargetVersion: 1, RunID: 1, Success: &success, LatencyMS: &latency},
		{ResultID: "-3-101", TargetID: -3, TargetVersion: 2, RunID: 1, Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.1"},
		{ResultID: "-3-101", TargetID: -3, TargetVersion: 2, RunID: 1, Success: &success, LatencyMS: &latency, ResolvedIP: "192.0.2.1"},
	}}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT enabled,last_heartbeat_at FROM v2_dns_probe WHERE id=\$1 FOR UPDATE`).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"enabled", "heartbeat"}).AddRow(1, time.Now().Unix()))
	for i := 0; i < 3; i++ {
		mock.ExpectQuery(`SELECT m.version,b.run_id FROM v2_dispatch_monitor`).WithArgs(int64(3), int64(7)).WillReturnRows(sqlmock.NewRows([]string{"version", "run"}).AddRow(2, 1))
		if i > 0 {
			mock.ExpectExec(`INSERT INTO v2_dispatch_monitor_state.*WHERE v2_dispatch_monitor_state.version<>EXCLUDED.version OR v2_dispatch_monitor_state.sequence<EXCLUDED.sequence`).WithArgs(int64(3), int64(7), int64(2), int64(101), true, int64(12), "", "192.0.2.1", sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, int64(2-i)))
		}
	}
	mock.ExpectCommit()
	result, err := s.ReportDispatchProbeResults(context.Background(), 7, request)
	if err != nil || result.Accepted != 1 || result.Skipped != 1 || result.Duplicates != 1 || len(result.GroupIDs) != 0 {
		t.Fatalf("%#v %v", result, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchReportsRequireFreshHeartbeatAndNegativeVersionedTargets(t *testing.T) {
	s, mock := newDispatchTestService(t)
	success := false
	for _, r := range []DNSProbeResult{{TargetID: 3, TargetVersion: 1}, {TargetID: math.MinInt64, TargetVersion: 1}, {TargetID: -3, TargetVersion: 0}} {
		r.Success = &success
		r.ResultID = "-3-100"
		if _, err := s.ReportDispatchProbeResults(context.Background(), 7, DNSProbeResultsRequest{Results: []DNSProbeResult{r}}); !errors.Is(err, ErrDNSProbeInvalidRequest) {
			t.Fatal(err)
		}
	}
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT enabled,last_heartbeat_at`).WillReturnRows(sqlmock.NewRows([]string{"enabled", "heartbeat"}).AddRow(1, time.Now().Unix()-100))
	mock.ExpectRollback()
	_, err := s.ReportDispatchProbeResults(context.Background(), 7, DNSProbeResultsRequest{Results: []DNSProbeResult{{TargetID: -3, TargetVersion: 1, RunID: 1, ResultID: "-3-100", Success: &success, Error: "timeout"}}})
	if !errors.Is(err, ErrDNSProbeHeartbeatRequired) {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestDispatchMonitorListShowsOwnershipAndMasksExpiredResults(t *testing.T) {
	s, mock := newDispatchTestService(t)
	mock.ExpectQuery(`SELECT id,host,check_port`).WillReturnRows(sqlmock.NewRows([]string{"id", "host", "port", "enabled", "interval", "timeout", "deleted"}).AddRow(3, "entry.example", 18443, true, 10, 500, false).AddRow(4, "removed.example", 443, true, 10, 500, false))
	now := time.Now().Unix()
	mock.ExpectQuery(`SELECT b.monitor_id,p.id,p.name`).WillReturnRows(sqlmock.NewRows([]string{"monitor", "probe", "name", "enabled", "heartbeat", "success", "latency", "error", "ip", "reported"}).AddRow(3, 7, "fresh", 1, now, true, 12, "", "192.0.2.1", now).AddRow(3, 8, "stale", 1, now, true, 12, "", "192.0.2.2", now-100))
	entries, err := s.ListDispatchMonitors(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("%#v %v", entries, err)
	}
	e := entries[0]
	if !reflect.DeepEqual(e.UserIDs, []string{"42"}) || len(e.States) != 2 || e.States[0].Success == nil || e.States[1].Success != nil || !e.States[1].Stale {
		t.Fatalf("%#v", e)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

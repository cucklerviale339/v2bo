package admin

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestDispatchHistoryTransitionsDoNotRepeatOrInventRecovery(t *testing.T) {
	at := time.Now().Unix()
	base := DispatchHistorySample{Source: "entry", Version: 1, RunID: 2, ReportedAt: at, Success: true, Status: "healthy"}
	cases := []struct {
		name                      string
		previous                  *DispatchHistorySample
		success                   bool
		streak, version, run, age int64
		event, status             string
	}{
		{"initial success", nil, true, 0, 1, 2, 0, "", "healthy"},
		{"first failure", nil, false, 0, 1, 2, 0, "down", "down"},
		{"failure transition", &base, false, 0, 1, 2, 0, "down", "down"},
		{"repeat failure", &DispatchHistorySample{Version: 1, RunID: 2, ReportedAt: at, Status: "down"}, false, 0, 1, 2, 0, "", "down"},
		{"recovery", &DispatchHistorySample{Version: 1, RunID: 2, ReportedAt: at, Status: "down"}, true, 0, 1, 2, 0, "recovered", "healthy"},
		{"new config", &DispatchHistorySample{Version: 1, RunID: 2, ReportedAt: at, Status: "down"}, true, 0, 2, 2, 0, "", "healthy"},
		{"new session", &DispatchHistorySample{Version: 1, RunID: 2, ReportedAt: at, Status: "down"}, true, 0, 1, 3, 0, "", "healthy"},
		{"expired baseline", &DispatchHistorySample{Version: 1, RunID: 2, ReportedAt: at - 3600, Status: "down"}, true, 0, 1, 2, 0, "", "healthy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := DispatchHistorySample{Source: "entry", Version: tc.version, RunID: tc.run, ReportedAt: at, Success: tc.success}
			event := dispatchHistoryTransition(tc.previous, &current, 30, 500)
			if event != tc.event || current.Status != tc.status {
				t.Fatalf("event=%q status=%q", event, current.Status)
			}
		})
	}
	previous := &DispatchHistorySample{Source: "pool", Version: 1, RunID: 2, ReportedAt: at, Status: "down"}
	first := DispatchHistorySample{Source: "pool", Version: 1, RunID: 2, ReportedAt: at, Success: true, Streak: 1}
	if event := dispatchHistoryTransition(previous, &first, 30, 500); event != "" || first.Status != "down" {
		t.Fatalf("pool recovered before two successes: %q %q", event, first.Status)
	}
	second := first
	second.Streak = 2
	if event := dispatchHistoryTransition(&first, &second, 30, 500); event != "recovered" {
		t.Fatalf("missing pool recovery: %q", event)
	}
}

func TestDispatchHistorySQLFailureDoesNotRollbackLiveState(t *testing.T) {
	s, mock := newDispatchTestService(t)
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE live_state").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SAVEPOINT dispatch_history").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT current_setting").WillReturnRows(sqlmock.NewRows([]string{"lock", "statement"}).AddRow("0", "0"))
	mock.ExpectExec("SELECT set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("WITH requested AS").WillReturnError(errors.New("history unavailable"))
	mock.ExpectExec("ROLLBACK TO SAVEPOINT dispatch_history").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("RELEASE SAVEPOINT dispatch_history").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("UPDATE live_state"); err != nil {
		t.Fatal(err)
	}
	s.persistDispatchHistory(context.Background(), tx, &dispatchHistoryBatch{samples: []DispatchHistorySample{{Source: "entry", TargetID: 3, ProbeID: 7}}})
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if s.dispatchHistoryLastError == "" {
		t.Fatal("history loss must be visible")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresDispatchHistoryLifecycle(t *testing.T) {
	f := newDispatchDeleteIntegration(t)
	pid := f.probe("history probe")
	f.save("inside.example", pid)
	task := f.tasks(pid)["inside.example"]
	report := func(task DNSProbeTask, seq int64, success bool) DNSProbeReportResult {
		t.Helper()
		latency := int64(12)
		errText := ""
		if !success {
			errText = "connection refused"
		}
		var latencyValue *int64
		if success {
			latencyValue = &latency
		}
		req := DNSProbeResultsRequest{Results: []DNSProbeResult{{ResultID: fmt.Sprintf("%d-%d", task.TargetID, seq), TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, Success: &success, LatencyMS: latencyValue, Error: errText}}}
		var result DNSProbeReportResult
		var err error
		if task.TargetID < -dispatchCheckOffset {
			result, err = f.s.ReportDispatchCheckResults(f.ctx, pid, req)
		} else {
			result, err = f.s.ReportDispatchProbeResults(f.ctx, pid, req)
		}
		if err != nil {
			t.Fatal(err)
		}
		if f.s.dispatchHistoryLastError != "" {
			t.Fatal(f.s.dispatchHistoryLastError)
		}
		return result
	}
	list := func(kind, source string) DispatchHistoryResult {
		t.Helper()
		r, err := f.s.ListDispatchHistory(f.ctx, DispatchHistoryRequest{Kind: kind, Source: source, Page: 1})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	report(task, 1, true)
	report(task, 2, false)
	report(task, 3, false)
	report(task, 4, true)
	if r := report(task, 4, true); r.Duplicates != 1 {
		t.Fatalf("duplicate accepted: %#v", r)
	}
	if r := list("sample", "entry"); r.Total != 4 || r.Data[0].Host != "inside.example" || r.Data[0].Port != 18443 || !r.Data[0].OwnershipKnown || len(r.Data[0].Ownership.UserIDs) == 0 {
		t.Fatalf("history snapshots: %#v", r)
	}
	if r := list("event", "entry"); r.Total != 2 || r.Data[0].EventType != "recovered" || r.Data[1].EventType != "down" {
		t.Fatalf("events: %#v", r)
	}
	ids, err := f.s.SaveDispatchPool(f.ctx, []DispatchPoolSave{{IP: "192.0.2.99", Name: "history pool", Port: 23456, Enabled: true, CheckIntervalSec: 30, TCPTimeoutMS: 500}})
	if err != nil {
		t.Fatal(err)
	}
	tasks, err := f.s.ListDispatchCheckTasks(f.ctx, pid)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("pool tasks: %v %v", tasks, err)
	}
	pool := tasks[0]
	report(pool, 10, false)
	report(pool, 11, true)
	if r := list("event", "pool"); r.Total != 1 {
		t.Fatal("premature pool recovery", r)
	}
	report(pool, 12, true)
	if r := list("event", "pool"); r.Total != 2 {
		t.Fatal("missing pool recovery", r)
	}
	before := f.snapshot("v2_dispatch_history")
	if err = f.s.RefreshDispatchPool(f.ctx, ids); err != nil {
		t.Fatal(err)
	}
	if err = f.s.DeleteDispatchMonitors(f.ctx, []string{"inside.example"}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(before) != fmt.Sprint(f.snapshot("v2_dispatch_history")) {
		t.Fatal("refresh/delete removed history")
	}
	restarted := f.newService()
	if err = restarted.ensureDispatchMonitorSchema(f.ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := restarted.ListDispatchHistory(f.ctx, DispatchHistoryRequest{Page: 1}); err != nil || r.Total != 7 {
		t.Fatalf("restart erased history: %#v %v", r, err)
	}
	// History SQL errors must not reject an accepted live result.
	f.s = restarted
	f.save("inside.example", pid)
	task = f.tasks(pid)["inside.example"]
	f.exec(`ALTER TABLE v2_dispatch_history ADD CONSTRAINT reject_history_test CHECK(target_id<0) NOT VALID`)
	yes := true
	latency := int64(12)
	result, err := f.s.ReportDispatchProbeResults(f.ctx, pid, DNSProbeResultsRequest{Results: []DNSProbeResult{{TargetID: task.TargetID, TargetVersion: task.TargetVersion, RunID: task.RunID, ResultID: fmt.Sprintf("%d-90", task.TargetID), Success: &yes, LatencyMS: &latency}}})
	if err != nil || result.Accepted != 1 || f.s.dispatchHistoryLastError == "" {
		t.Fatalf("history failure broke live report: %#v %v", result, err)
	}
	f.exec(`ALTER TABLE v2_dispatch_history DROP CONSTRAINT reject_history_test`)
	f.exec(`UPDATE v2_dispatch_history SET created_at=$1 WHERE kind='sample'`, time.Now().Add(-25*time.Hour).Unix())
	if err = f.s.cleanupDispatchHistory(f.ctx); err != nil {
		t.Fatal(err)
	}
	var samples, events int
	if err = f.db.QueryRow(`SELECT count(*) FILTER(WHERE kind='sample'),count(*) FILTER(WHERE kind='event') FROM v2_dispatch_history`).Scan(&samples, &events); err != nil {
		t.Fatal(err)
	}
	if samples != 0 || events != 4 {
		t.Fatalf("retention samples=%d events=%d", samples, events)
	}
}

func TestDispatchHistoryRejectsInvalidFiltersWithoutDatabase(t *testing.T) {
	s := &DBService{}
	for _, req := range []DispatchHistoryRequest{{Page: 0}, {Page: 1, Source: "dns"}, {Page: 1, Kind: "garbage"}, {Page: 1, From: 20, To: 10}, {Page: 1, EventType: "fake"}} {
		if _, err := s.ListDispatchHistory(context.Background(), req); !errors.Is(err, ErrDNSProbeInvalidRequest) {
			t.Fatalf("accepted %#v: %v", req, err)
		}
	}
}

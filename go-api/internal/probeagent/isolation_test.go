package probeagent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAuxiliaryOutageAndRollbackKeepDNSReporting(t *testing.T) {
	var rollback atomic.Bool
	var dnsReports, auxRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/probe/heartbeat":
			w.Write([]byte(`{"data":{}}`))
		case "/api/v1/probe/tasks":
			json.NewEncoder(w).Encode(map[string]any{"monitor_transport": !rollback.Load(), "data": []Task{{TargetID: 7, CheckHost: "localhost", CheckPort: 443, CheckIntervalSec: 1}}})
		case "/api/v1/probe/results":
			var req struct {
				Results []Result `json:"results"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			for _, r := range req.Results {
				if r.TargetID < 0 {
					t.Error("auxiliary result leaked into DNS batch")
				}
			}
			dnsReports.Add(1)
			w.Write([]byte(`{"data":{}}`))
		case "/api/v1/probe/monitor-tasks":
			auxRequests.Add(1)
			if rollback.Load() {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []Task{{TargetID: -7, TargetVersion: 1, RunID: 1, CheckHost: "localhost", CheckPort: 443, CheckIntervalSec: 1}}})
		case "/api/v1/probe/monitor-results":
			if rollback.Load() {
				http.NotFound(w, r)
				return
			}
			http.Error(w, "auxiliary DB unavailable", 500)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	checker := &immediateChecker{started: make(chan struct{}), stopped: make(chan struct{})}
	a, err := New(Config{APIURL: server.URL, Token: "test", Interval: 20 * time.Millisecond}, WithHTTPClient(server.Client()), WithChecker(checker), WithInsecureLocalHTTP())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); a.Run(ctx) }()
	wait := func(condition func() bool) {
		t.Helper()
		deadline := time.After(4 * time.Second)
		for !condition() {
			select {
			case <-deadline:
				t.Fatal("timed out waiting for independent DNS reporting")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	wait(func() bool { return dnsReports.Load() > 0 && auxRequests.Load() > 0 })
	rollback.Store(true)
	previous := dnsReports.Load()
	wait(func() bool { return dnsReports.Load() > previous })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent did not stop")
	}
}
func TestRollbackDiscardsOnlyUnsupportedAuxiliaryQueue(t *testing.T) {
	var legacy atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/probe/monitor-results" {
			http.NotFound(w, r)
			return
		}
		legacy.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()
	a, err := New(Config{APIURL: server.URL, Token: "test", Interval: time.Second}, WithHTTPClient(server.Client()), WithInsecureLocalHTTP())
	if err != nil {
		t.Fatal(err)
	}
	a.auxiliary = true
	if pending := a.flush(context.Background(), []Result{{TargetID: -7, ResultID: "-7-1"}}); len(pending) != 0 {
		t.Fatal("unsupported queue retained")
	}
	a.auxiliary = false
	if pending := a.flush(context.Background(), []Result{{TargetID: -7}, {TargetID: 7, ResultID: "7-1"}}); len(pending) != 0 || legacy.Load() != 1 {
		t.Fatal("DNS queue blocked")
	}
}

package probeagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type concurrentAuxiliaryChecker struct {
	active  atomic.Int64
	peak    atomic.Int64
	started chan string
}

func (c *concurrentAuxiliaryChecker) Check(ctx context.Context, host string, _ int, _ time.Duration) CheckResult {
	n := c.active.Add(1)
	defer c.active.Add(-1)
	for old := c.peak.Load(); n > old; old = c.peak.Load() {
		if c.peak.CompareAndSwap(old, n) {
			break
		}
	}
	select {
	case c.started <- host:
	case <-ctx.Done():
		return CheckResult{Error: "cancelled"}
	}
	<-ctx.Done()
	return CheckResult{Error: "cancelled"}
}

func TestAuxiliaryEntryAndPoolChecksRunIndependently(t *testing.T) {
	// More than 64 blocked checks prove neither the former serial slot nor
	// the earlier 64-check semaphore limits independent target workers.
	const targetCount = 70
	tasks := make([]Task, targetCount)
	for i := range tasks {
		id := -int64(i + 1)
		if i%2 != 0 {
			id -= 1 << 60
		}
		tasks[i] = Task{TargetID: id, CheckHost: fmt.Sprintf("target-%d.test", i), CheckPort: 443, CheckIntervalSec: 3600}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/probe/monitor-tasks":
			json.NewEncoder(w).Encode(map[string]any{"data": tasks})
		case "/api/v1/probe/monitor-results":
			w.Write([]byte(`{"data":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	checker := &concurrentAuxiliaryChecker{started: make(chan string, targetCount)}
	a, err := New(Config{APIURL: server.URL, Token: "test", Interval: 20 * time.Millisecond}, WithHTTPClient(server.Client()), WithChecker(checker), WithInsecureLocalHTTP())
	if err != nil {
		t.Fatal(err)
	}
	a.auxiliary = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("independent checks did not cancel")
		}
	})
	seen := map[string]bool{}
	for i := 0; i < len(tasks); i++ {
		select {
		case host := <-checker.started:
			if seen[host] {
				t.Fatal("target repeated before remaining targets ran")
			}
			seen[host] = true
		case <-time.After(time.Second):
			t.Fatal("target did not start while other checks were blocked")
		}
	}
	// All checks must be in flight together and cancel without leaking workers.
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on independent checks")
	}
	if checker.peak.Load() != targetCount || checker.active.Load() != 0 {
		t.Fatalf("peak=%d active=%d", checker.peak.Load(), checker.active.Load())
	}
}

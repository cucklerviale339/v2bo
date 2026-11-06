package admin

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInvestigationBatchBudgetRotationAndFailures(t *testing.T) {
	ids := make([]int64, 45)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	var seen []int64
	process := func(ctx context.Context, id int64) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > investigationActionBudget {
			t.Fatal("action has no independent bounded deadline")
		}
		seen = append(seen, id)
		return nil
	}
	cursor, err := investigationBatch(context.Background(), ids, 0, process)
	if err != nil || cursor != 30 || !reflect.DeepEqual(seen, ids[:30]) {
		t.Fatal(cursor, seen, err)
	}
	seen = nil
	cursor, err = investigationBatch(context.Background(), ids, cursor, process)
	want := append(append([]int64{}, ids[30:]...), ids[:15]...)
	if err != nil || cursor != 15 || !reflect.DeepEqual(seen, want) {
		t.Fatal("later roots starved", cursor, seen, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), investigationActionBudget-time.Millisecond)
	defer cancel()
	seen = nil
	cursor, err = investigationBatch(ctx, ids, 15, process)
	if err != nil || cursor != 15 || len(seen) != 0 {
		t.Fatal("ordinary budget yield became an error or advanced cursor", cursor, seen, err)
	}
	injected := errors.New("injected group failure")
	seen = nil
	cursor, err = investigationBatch(context.Background(), []int64{1, 2, 3}, 0, func(_ context.Context, id int64) error {
		seen = append(seen, id)
		if id == 1 {
			return injected
		}
		return nil
	})
	if !errors.Is(err, injected) || !strings.Contains(err.Error(), "#1") || cursor != 3 || !reflect.DeepEqual(seen, []int64{1, 2, 3}) {
		t.Fatal("failed group stopped other roots or lost diagnostics", cursor, seen, err)
	}
	cursor, err = investigationBatch(context.Background(), ids, 15, func(context.Context, int64) error { return ErrInvestigationBusy })
	if err != nil || cursor != 15 {
		t.Fatal("manual contention consumed cursor or reported failure", cursor, err)
	}
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err = investigationBatch(canceled, ids, cursor, process); !errors.Is(err, context.Canceled) {
		t.Fatal("shutdown cancellation hidden", err)
	}
}

func TestPostgresInvestigationManualWaitsForWorkerAndKeepsRound(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	before := f.snapshot("v2_node_address_rule", "v2_insider_rule", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}) }()
	deadline := time.Now().Add(time.Second)
	for {
		f.s.dispatchAutoSplitMu.Lock()
		pending := f.s.investigationManualPending
		f.s.dispatchAutoSplitMu.Unlock()
		if pending > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("manual request did not register priority")
		}
		time.Sleep(time.Millisecond)
	}
	if err = f.s.processInvestigationAction(f.ctx, g.ID, 0, false); !errors.Is(err, ErrInvestigationBusy) {
		t.Fatal("worker failed to yield to pending manual action", err)
	}
	// Reproduce the old 500 ms lock failure, then release within the new wait.
	select {
	case err = <-done:
		t.Fatal("manual request failed before lock released", err)
	case <-time.After(700 * time.Millisecond):
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if f.successfulEvents() != 1 || !reflect.DeepEqual(before, f.snapshot("v2_node_address_rule", "v2_insider_rule", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")) {
		t.Fatal("wait lost receipts or failed to apply exactly once", f.groups())
	}
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			f.assertCheckPort(child.Host, 18443)
		}
	}
	f.s.dispatchAutoSplitMu.Lock()
	pending := f.s.investigationManualPending
	f.s.dispatchAutoSplitMu.Unlock()
	if pending != 0 {
		t.Fatal("manual priority leaked after request", pending)
	}
}

func TestPostgresInvestigationLockBusyPreservesData(t *testing.T) {
	f := newInvestigationIntegration(t)
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")
	waiter, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Rollback()
	if err = acquireInvestigationLock(f.ctx, waiter, true); !errors.Is(err, ErrInvestigationBusy) {
		t.Fatal("busy lock not surfaced as retryable", err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor")) {
		t.Fatal("busy request changed dispatch data")
	}
}

func waitInvestigationManualPending(t *testing.T, s *DBService, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.dispatchAutoSplitMu.Lock()
		pending := s.investigationManualPending
		s.dispatchAutoSplitMu.Unlock()
		if pending == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("manual pending=%d, want %d", pending, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPostgresInvestigationConcurrentManualAppliesOnce(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212", "192.0.2.213", "192.0.2.214")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	before := f.snapshot("v2_node_address_rule", "v2_insider_rule", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- f.s.TriggerInvestigation(f.ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}) }()
	}
	waitInvestigationManualPending(t, f.s, 2)
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	succeeded, rejected := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case err = <-done:
			if err == nil {
				succeeded++
			} else if errors.Is(err, ErrDNSProbeInvalidRequest) {
				rejected++
			} else {
				t.Fatal(err)
			}
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		}
	}
	var audits int
	if err = f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_event WHERE kind='manual_trigger'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 || rejected != 1 || f.successfulEvents() != 1 || audits != 1 {
		t.Fatal("duplicate click repeated allocation", succeeded, rejected, f.successfulEvents(), audits)
	}
	children := 0
	for _, child := range f.groups() {
		if child.ParentID == g.ID {
			children++
			f.assertCheckPort(child.Host, 18443)
		}
	}
	if children != 2 || !reflect.DeepEqual(before, f.snapshot("v2_node_address_rule", "v2_insider_rule", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")) {
		t.Fatal("duplicate click changed the round or dispatch source", children)
	}
	waitInvestigationManualPending(t, f.s, 0)
}

func TestPostgresInvestigationCanceledManualReleasesWorker(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	before := f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")
	tx, err := f.db.BeginTx(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(f.ctx, `SELECT pg_advisory_xact_lock(7642309023)`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.s.TriggerInvestigation(ctx, InvestigationAction{ID: g.ID, Revision: g.Revision}) }()
	waitInvestigationManualPending(t, f.s, 1)
	cancel()
	select {
	case err = <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("request cancellation lost", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled request kept waiting for the lock")
	}
	waitInvestigationManualPending(t, f.s, 0)
	if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group", "v2_dispatch_investigation_member", "v2_dispatch_investigation_event", "v2_dispatch_monitor", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent")) {
		t.Fatal("canceled request changed observation or dispatch data")
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("worker failed to resume the original observed round", f.groups())
	}
}

func TestPostgresInvestigationLargeRosterCycle(t *testing.T) {
	f := newInvestigationIntegration(t)
	base := f.group("base.example")
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,created_at,updated_at)
SELECT id,'load-'||id||'@example.test','hash',lpad(id::text,36,'0'),lpad(id::text,32,'0'),1,1 FROM generate_series(10000,52999) id`)
	now := time.Now().Unix()
	for n := 0; n < 43; n++ {
		var id int64
		if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_group(name,kind,host,monitor_id,epoch_at,created_at) VALUES('bulk','candidate','base.example',$1,$2,$2) RETURNING id`, base.MonitorID, now-100000).Scan(&id); err != nil {
			t.Fatal(err)
		}
		f.exec(`UPDATE v2_dispatch_investigation_group SET root_id=id WHERE id=$1`, id)
		f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id) SELECT $1,'base.example',id,$1 FROM generate_series($2::bigint,$2::bigint+999) id`, id, 10000+n*1000)
	}
	// A day of retained history used to be decoded again for every healthy
	// group. The latest success alone must produce the same recovered baseline.
	f.exec(`INSERT INTO v2_dispatch_history(source,target_id,probe_id,version,run_id,sequence,kind,host,port,success,payload,created_at)
SELECT 'entry',s.monitor_id,s.probe_id,s.version,b.run_id,-n,'sample','base.example',18443,TRUE,
jsonb_build_object('version',s.version,'run_id',b.run_id,'sequence',-n,'success',TRUE,'reported_at',$2::bigint-n*30),$2::bigint-n*30
FROM v2_dispatch_monitor_state s JOIN v2_dispatch_monitor_probe b ON b.monitor_id=s.monitor_id AND b.probe_id=s.probe_id CROSS JOIN generate_series(1,2880) n WHERE s.monitor_id=$1`, base.MonitorID, now)
	before := f.snapshot("v2_dispatch_investigation_member", "v2_node_address_rule", "v2_insider_rule")
	start := time.Now()
	for i := 0; i < 8; i++ {
		if err := f.s.runInvestigationCycle(f.ctx); err != nil {
			t.Fatal("large inventory failed rather than yielding", err)
		}
		var remaining int
		if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_group WHERE name='bulk' AND ready_at=0`).Scan(&remaining); err != nil {
			t.Fatal(err)
		}
		if remaining == 0 {
			break
		}
	}
	var pending int
	if err := f.db.QueryRow(`SELECT count(*) FROM v2_dispatch_investigation_group WHERE name='bulk' AND (ready_at=0 OR generation<>1 OR epoch_at<>$1 OR reason<>'正常观察中')`, now-100000).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_node_address_rule", "v2_insider_rule")) {
		t.Fatal("later groups starved or roster/round changed", pending)
	}
	view, err := f.s.GetInvestigation(f.ctx, 1)
	if err != nil || view.WorkerError != "" {
		t.Fatal("successful continuation still shows worker failure", err, view.WorkerError)
	}
	t.Log(fmt.Sprintf("45 active groups, 43000 added members and 2880 history samples completed in %s", time.Since(start)))
}

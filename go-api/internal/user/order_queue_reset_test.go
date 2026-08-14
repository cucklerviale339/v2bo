package user

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"forest/go-api/internal/config"
	"github.com/DATA-DOG/go-sqlmock"
)

const trafficResetCycleKeyPrefix = "TRAFFIC_RESET_CYCLE_USER_"
const trafficResetCandidateQueryPattern = `(?s)SELECT u.id, u.plan_id, u.u, u.d, COALESCE\(u.expired_at, 0\), u.updated_at,\s+COALESCE\(NULLIF\(CASE WHEN u.traffic_reset_anchor_plan_id = u.plan_id THEN u.traffic_reset_anchor_at ELSE 0 END, 0\),.*SELECT MAX\(COALESCE\(o.paid_at, o.created_at\)\).*o.type IN \(1, 3\).*o.period NOT IN \('onetime_price', 'reset_price', 'deposit'\).*COALESCE\(u.traffic_reset_anchor_plan_id, 0\).*COALESCE\(u.traffic_reset_at, 0\), p.reset_traffic_method\s+FROM v2_user u\s+JOIN v2_plan p ON p.id = u.plan_id\s+WHERE u.plan_id IS NOT NULL AND u.expired_at > \$1\s+ORDER BY u.id ASC`

func newTrafficResetRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"id", "plan_id", "u", "d", "expired_at", "updated_at", "reset_anchor_at", "stored_reset_anchor_at", "stored_reset_anchor_plan_id", "subscription_started_at", "last_traffic_reset_at", "reset_traffic_method"})
}

func expectNoTrafficResetCandidates(mock sqlmock.Sqlmock) {
	dailyMarker := time.Now().Format("2006-01-02")
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows())
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, dailyMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func TestHandlePendingOrdersBackfillsMonthlyTrafficReset(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		CommissionAutoCheckEnable: false,
		OrderKeepDays:             0,
		ResetTrafficMethod:        0,
	}, db)

	now := time.Now()
	dailyMarker := now.Format("2006-01-02")
	expiredAt := now.Add(7 * 24 * time.Hour).Unix()
	cycleStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	staleUpdatedAt := cycleStart - 3600
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(0), cycleStart)

	mock.ExpectQuery(`SELECT trade_no\s+FROM v2_order\s+WHERE status IN \(0, 1\)`).
		WithArgs(orderHandleBatchLimit).
		WillReturnRows(sqlmock.NewRows([]string{"trade_no"}))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, staleUpdatedAt, staleUpdatedAt, staleUpdatedAt, int64(7), staleUpdatedAt, int64(0), nil),
		)
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
		WithArgs(int64(10), staleUpdatedAt, int64(7), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"10", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, dailyMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := service.HandlePendingOrders(context.Background()); err != nil {
		t.Fatalf("handle pending orders: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestHandlePendingOrdersSkipsTrafficResetWhenCycleAlreadyApplied(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		CommissionAutoCheckEnable: false,
		OrderKeepDays:             0,
		ResetTrafficMethod:        0,
	}, db)

	now := time.Now()
	dailyMarker := now.Format("2006-01-02")
	expiredAt := now.Add(7 * 24 * time.Hour).Unix()
	cycleStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(0), cycleStart)

	mock.ExpectQuery(`SELECT trade_no\s+FROM v2_order\s+WHERE status IN \(0, 1\)`).
		WithArgs(orderHandleBatchLimit).
		WillReturnRows(sqlmock.NewRows([]string{"trade_no"}))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, cycleStart-3600, cycleStart-3600, cycleStart-3600, int64(7), cycleStart-3600, int64(0), nil),
		)
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnRows(sqlmock.NewRows([]string{"v", "expire_at"}).
			AddRow(expectedMarker, int64(0)),
		)
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, dailyMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := service.HandlePendingOrders(context.Background()); err != nil {
		t.Fatalf("handle pending orders: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestHandlePendingOrdersSeedsMonthlyTrafficCycleWithoutResetForFreshSubscription(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		CommissionAutoCheckEnable: false,
		OrderKeepDays:             0,
		ResetTrafficMethod:        0,
	}, db)

	now := time.Now()
	dailyMarker := now.Format("2006-01-02")
	expiredAt := now.Add(7 * 24 * time.Hour).Unix()
	cycleStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	freshUpdatedAt := cycleStart + 3600
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(0), cycleStart)

	mock.ExpectQuery(`SELECT trade_no\s+FROM v2_order\s+WHERE status IN \(0, 1\)`).
		WithArgs(orderHandleBatchLimit).
		WillReturnRows(sqlmock.NewRows([]string{"trade_no"}))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, freshUpdatedAt, freshUpdatedAt, freshUpdatedAt, int64(7), freshUpdatedAt, int64(0), nil),
		)
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"10", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, dailyMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := service.HandlePendingOrders(context.Background()); err != nil {
		t.Fatalf("handle pending orders: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestHandlePendingOrdersResetsOldSubscriptionAfterTrafficReportUpdatedAt(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		CommissionAutoCheckEnable: false,
		OrderKeepDays:             0,
		ResetTrafficMethod:        0,
	}, db)

	now := time.Now()
	dailyMarker := now.Format("2006-01-02")
	expiredAt := now.Add(7 * 24 * time.Hour).Unix()
	cycleStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	trafficUpdatedAt := cycleStart + 3600
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(0), cycleStart)

	mock.ExpectQuery(`SELECT trade_no\s+FROM v2_order\s+WHERE status IN \(0, 1\)`).
		WithArgs(orderHandleBatchLimit).
		WillReturnRows(sqlmock.NewRows([]string{"trade_no"}))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, trafficUpdatedAt, cycleStart-86400, cycleStart-86400, int64(7), cycleStart-86400, int64(0), nil),
		)
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
		WithArgs(int64(10), cycleStart-86400, int64(7), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"10", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, dailyMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := service.HandlePendingOrders(context.Background()); err != nil {
		t.Fatalf("handle pending orders: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSweepTrafficResetsReturnsSummaryCounts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		ResetTrafficMethod: 0,
	}, db)

	now := time.Now()
	expiredAt := now.Add(7 * 24 * time.Hour).Unix()
	cycleStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location()).Unix()
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(0), cycleStart)

	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, cycleStart-3600, cycleStart-3600, cycleStart-3600, int64(7), cycleStart-3600, int64(0), nil).
			AddRow(int64(11), int64(7), int64(12), int64(34), expiredAt, cycleStart+3600, cycleStart-3600, cycleStart-3600, int64(7), cycleStart-3600, int64(0), nil).
			AddRow(int64(12), int64(7), int64(56), int64(78), expiredAt, cycleStart-3600, cycleStart-3600, cycleStart-3600, int64(7), cycleStart-3600, int64(0), nil),
		)
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
		WithArgs(int64(10), cycleStart-3600, int64(7), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"10", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "11").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
		WithArgs(int64(11), cycleStart-3600, int64(7), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"11", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "12").
		WillReturnRows(sqlmock.NewRows([]string{"v", "expire_at"}).
			AddRow(expectedMarker, int64(0)),
		)

	result, err := service.SweepTrafficResets(context.Background())
	if err != nil {
		t.Fatalf("sweep traffic resets: %v", err)
	}
	if result.Scanned != 3 || result.Reset != 2 || result.MarkedOnly != 0 || result.Skipped != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSweepTrafficResetsExcludesNoExpiryUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{
		ResetTrafficMethod: 0,
	}, db)

	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(newTrafficResetRows())

	result, err := service.SweepTrafficResets(context.Background())
	if err != nil {
		t.Fatalf("sweep traffic resets: %v", err)
	}
	if result.Reset != 0 || result.Scanned != 0 {
		t.Fatalf("expected no reset for no-expiry users, got %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestResetAllTrafficUsageZerosActiveExpiringUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{}, db)

	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_at = \$2, updated_at = \$1\s+WHERE plan_id IS NOT NULL AND expired_at > \$1`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 12000))

	result, err := service.ResetAllTrafficUsage(context.Background())
	if err != nil {
		t.Fatalf("reset all traffic usage: %v", err)
	}
	if result.Scanned != 12000 || result.Reset != 12000 || result.MarkedOnly != 0 || result.Skipped != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestTrafficResetSweepSupportsAllResetMethods(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{ResetTrafficMethod: 0}, db)
	now := time.Date(2026, time.January, 1, 0, 5, 0, 0, time.Local)
	cycleStart := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.Local).Unix()
	expiredAt := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.Local).Unix()
	startedAt := cycleStart - 86400
	monthlyAnchorAt := time.Date(2025, time.January, 1, 12, 0, 0, 0, time.Local).Unix()

	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(now.Unix()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(70), int64(10), int64(20), expiredAt, now.Unix(), startedAt, startedAt, int64(70), startedAt, int64(0), int64(0)).
			AddRow(int64(11), int64(71), int64(10), int64(20), expiredAt, now.Unix(), monthlyAnchorAt, monthlyAnchorAt, int64(71), monthlyAnchorAt, int64(0), int64(1)).
			AddRow(int64(12), int64(72), int64(10), int64(20), expiredAt, now.Unix(), startedAt, startedAt, int64(72), startedAt, int64(0), int64(2)).
			AddRow(int64(13), int64(73), int64(10), int64(20), expiredAt, now.Unix(), startedAt, startedAt, int64(73), startedAt, int64(0), int64(3)).
			AddRow(int64(14), int64(74), int64(10), int64(20), expiredAt, now.Unix(), startedAt, startedAt, int64(74), startedAt, int64(0), int64(4)),
		)

	for _, item := range []struct {
		userID int64
		planID int64
		method int64
	}{
		{userID: 10, planID: 70, method: 0},
		{userID: 11, planID: 71, method: 1},
		{userID: 13, planID: 73, method: 3},
		{userID: 14, planID: 74, method: 4},
	} {
		expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", item.planID, item.method, cycleStart)
		mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
			WithArgs(fmt.Sprintf("%s%d", trafficResetCycleKeyPrefix, item.userID)).
			WillReturnError(sql.ErrNoRows)
		anchorAt := startedAt
		if item.method == 1 {
			anchorAt = monthlyAnchorAt
		}
		mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
			WithArgs(item.userID, anchorAt, item.planID, sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
			WithArgs(fmt.Sprintf("%s%d", trafficResetCycleKeyPrefix, item.userID), expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}

	result, err := service.runTrafficResetSweepAt(context.Background(), now, false, false)
	if err != nil {
		t.Fatalf("traffic reset sweep: %v", err)
	}
	if result.Scanned != 5 || result.Reset != 4 || result.MarkedOnly != 0 || result.Skipped != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestDailyTrafficResetSweepRunsOncePerDay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{ResetTrafficMethod: 1}, db)
	now := time.Date(2026, time.May, 2, 0, 5, 0, 0, time.Local)
	marker := now.Format("2006-01-02")

	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetDailySweepKVKey).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(now.Unix()).
		WillReturnRows(newTrafficResetRows())
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetDailySweepKVKey, marker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	result, err := service.runDailyTrafficResetSweep(context.Background(), now)
	if err != nil {
		t.Fatalf("daily reset sweep: %v", err)
	}
	if result.Scanned != 0 || result.Reset != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestTrafficResetMonthlyAnchorUsesOrderDay(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*60*60)
	anchorAt := time.Date(2026, time.January, 15, 18, 30, 0, 0, loc).Unix()

	tests := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{
			name: "on order day",
			now:  time.Date(2026, time.August, 15, 0, 5, 0, 0, loc),
			want: time.Date(2026, time.August, 15, 0, 0, 0, 0, loc),
		},
		{
			name: "before order day",
			now:  time.Date(2026, time.August, 14, 23, 59, 0, 0, loc),
			want: time.Date(2026, time.July, 15, 0, 0, 0, 0, loc),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trafficResetMonthlyAnchor(anchorAt, tt.now)
			if !got.Equal(tt.want) {
				t.Fatalf("unexpected cycle start: got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTrafficResetMonthlyAnchorClipsOrderDayToMonthEnd(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*60*60)
	anchorAt := time.Date(2026, time.January, 31, 12, 0, 0, 0, loc).Unix()

	tests := []struct {
		name string
		now  time.Time
		want time.Time
	}{
		{
			name: "non-leap February",
			now:  time.Date(2026, time.February, 28, 0, 5, 0, 0, loc),
			want: time.Date(2026, time.February, 28, 0, 0, 0, 0, loc),
		},
		{
			name: "leap February",
			now:  time.Date(2028, time.February, 29, 0, 5, 0, 0, loc),
			want: time.Date(2028, time.February, 29, 0, 0, 0, 0, loc),
		},
		{
			name: "thirty day month",
			now:  time.Date(2026, time.April, 30, 0, 5, 0, 0, loc),
			want: time.Date(2026, time.April, 30, 0, 0, 0, 0, loc),
		},
		{
			name: "before month end after shorter month",
			now:  time.Date(2026, time.March, 30, 0, 5, 0, 0, loc),
			want: time.Date(2026, time.February, 28, 0, 0, 0, 0, loc),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trafficResetMonthlyAnchor(anchorAt, tt.now)
			if !got.Equal(tt.want) {
				t.Fatalf("unexpected clipped cycle start: got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestTrafficResetCandidatePersistsFirstOrderAnchorAcrossRenewals(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	service := NewDBService(config.Config{ResetTrafficMethod: 1}, db)
	loc := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2026, time.August, 15, 0, 5, 0, 0, loc)
	orderAnchorAt := time.Date(2026, time.June, 15, 12, 0, 0, 0, loc).Unix()
	expiredAt := time.Date(2027, time.September, 22, 12, 0, 0, 0, loc).Unix()
	cycleStart := time.Date(2026, time.August, 15, 0, 0, 0, 0, loc).Unix()
	expectedMarker := fmt.Sprintf("plan:%d|method:%d|start:%d", int64(7), int64(1), cycleStart)

	mock.ExpectQuery(trafficResetCandidateQueryPattern).
		WithArgs(now.Unix()).
		WillReturnRows(newTrafficResetRows().
			AddRow(int64(10), int64(7), int64(123), int64(456), expiredAt, now.Unix(), orderAnchorAt, orderAnchorAt, int64(9), orderAnchorAt, int64(0), int64(1)),
		)
	mock.ExpectExec(`UPDATE v2_user SET traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3 WHERE id = \$1`).
		WithArgs(int64(10), orderAnchorAt, int64(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT v, expire_at FROM v2_runtime_kv WHERE k = \$1 LIMIT 1`).
		WithArgs(trafficResetCycleKeyPrefix + "10").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(`UPDATE v2_user\s+SET u = 0, d = 0, traffic_reset_anchor_at = \$2, traffic_reset_anchor_plan_id = \$3, traffic_reset_at = \$4, updated_at = \$5\s+WHERE id = \$1`).
		WithArgs(int64(10), orderAnchorAt, int64(7), sqlmock.AnyArg(), now.Unix()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`INSERT INTO v2_runtime_kv \(k, v, expire_at, created_at, updated_at\)`).
		WithArgs(trafficResetCycleKeyPrefix+"10", expectedMarker, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	result, err := service.runTrafficResetSweepAt(context.Background(), now, false, false)
	if err != nil {
		t.Fatalf("traffic reset sweep: %v", err)
	}
	if result.Reset != 1 || result.Scanned != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

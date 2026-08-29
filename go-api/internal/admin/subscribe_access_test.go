package admin

import (
	"context"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectSubscribeAccessSchema(mock sqlmock.Sqlmock) {
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_subscribe_access_log`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_subscribe_access_log_accessed_at`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_subscribe_access_log_user_at`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_subscribe_access_config`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO v2_subscribe_access_config`).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

func expectSubscribeAccessStatsExtras(mock sqlmock.Sqlmock) {
	mock.ExpectQuery(`SELECT client_ip, COUNT\(\*\) FROM v2_subscribe_access_log`).
		WillReturnRows(sqlmock.NewRows([]string{"ip", "count"}))
	mock.ExpectQuery(`SELECT user_agent, COUNT\(\*\) FROM v2_subscribe_access_log`).
		WillReturnRows(sqlmock.NewRows([]string{"ua", "count"}))
	mock.ExpectQuery(`SELECT l.id, l.user_id`).
		WillReturnRows(sqlmock.NewRows([]string{"id", "user_id", "email", "ip", "ua", "accessed_at"}))
	mock.ExpectQuery(`SELECT log_keep_days FROM v2_subscribe_access_config`).
		WillReturnRows(sqlmock.NewRows([]string{"log_keep_days"}).AddRow(int64(7)))
}

func TestGetSubscribeAccessStatsSearchesByUserID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectQuery(`SELECT COUNT\(\*\), COUNT\(DISTINCT user_id\),`).
		WillReturnRows(sqlmock.NewRows([]string{"requests", "users", "ips", "user_agents"}).AddRow(8, 2, 3, 4))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE l.user_id = $1`)).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectQuery(`WHERE l\.user_id = \$1[\s\S]+LIMIT \$2 OFFSET \$3`).
		WithArgs(int64(9), int64(10), int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "email", "count", "ip_count", "ua_count", "last_at", "last_ip", "last_ua"}).
			AddRow(int64(9), "demo@example.com", int64(8), int64(3), int64(4), int64(123), "203.0.113.7", "Clash/1.0"))
	expectSubscribeAccessStatsExtras(mock)

	result, err := (&DBService{db: db}).GetSubscribeAccessStats(context.Background(), SubscribeAccessStatsRequest{
		Keyword: " 9 ", Current: 2, PageSize: 10,
	})
	if err != nil {
		t.Fatalf("get subscribe access stats: %v", err)
	}
	if result["total"] != int64(1) || result["current"] != int64(2) {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestGetSubscribeAccessStatsSearchesByEmail(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectQuery(`SELECT COUNT\(\*\), COUNT\(DISTINCT user_id\),`).
		WillReturnRows(sqlmock.NewRows([]string{"requests", "users", "ips", "user_agents"}).AddRow(0, 0, 0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE LOWER(u.email) LIKE LOWER($1)`)).
		WithArgs("%Demo@Example.com%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	mock.ExpectQuery(`WHERE LOWER\(u\.email\) LIKE LOWER\(\$1\)[\s\S]+LIMIT \$2 OFFSET \$3`).
		WithArgs("%Demo@Example.com%", int64(20), int64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "email", "count", "ip_count", "ua_count", "last_at", "last_ip", "last_ua"}))
	expectSubscribeAccessStatsExtras(mock)

	_, err = (&DBService{db: db}).GetSubscribeAccessStats(context.Background(), SubscribeAccessStatsRequest{
		Keyword: " Demo@Example.com ",
	})
	if err != nil {
		t.Fatalf("get subscribe access stats: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSearchSubscribeAccessByUAAggregatesMatchingUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectQuery(`SELECT COUNT\(DISTINCT user_id\).*LOWER\(user_agent\) LIKE LOWER\(\$1\)`).
		WithArgs("%Clash%").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(`WHERE LOWER\(l\.user_agent\) LIKE LOWER\(\$1\)[\s\S]+LIMIT \$2 OFFSET \$3`).
		WithArgs("%Clash%", int64(10), int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "email", "count", "ip_count", "ua_count", "last_at"}).
			AddRow(int64(9), "demo@example.com", int64(5), int64(2), int64(1), int64(123)))

	result, err := (&DBService{db: db}).SearchSubscribeAccessByUA(context.Background(), " Clash ", 2, 10)
	if err != nil {
		t.Fatalf("search subscribe access by UA: %v", err)
	}
	data := result["data"].([]map[string]any)
	if result["total"] != int64(1) || len(data) != 1 || data[0]["count"] != int64(5) {
		t.Fatalf("unexpected result: %#v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestSetSubscribeAccessRetentionUpdatesAndCleans(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectExec(`UPDATE v2_subscribe_access_config SET log_keep_days = \$1`).
		WithArgs(int64(30), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`DELETE FROM v2_subscribe_access_log WHERE accessed_at < \$1`).
		WithArgs(sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 3))

	ok, err := (&DBService{db: db}).SetSubscribeAccessRetention(context.Background(), 30)
	if err != nil || !ok {
		t.Fatalf("set subscribe access retention: ok=%v err=%v", ok, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestGetDailyLowTrafficUsersExcludesZeroAndCapsAt200KB(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectQuery(`HAVING SUM\([\s\S]+\) > 0[\s\S]+<= \$3[\s\S]+SELECT COUNT\(\*\) FROM daily`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), int64(200*1024)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(`HAVING SUM\([\s\S]+\) > 0[\s\S]+<= \$3[\s\S]+LEFT JOIN LATERAL[\s\S]+LIMIT \$4 OFFSET \$5`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), int64(200*1024), int64(10), int64(10)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "email", "traffic_bytes", "last_ip", "last_ua", "last_at"}).
			AddRow(int64(9), "demo@example.com", int64(102400), "203.0.113.7", "Clash/1.0", int64(123)))

	result, err := (&DBService{db: db}).GetDailyLowTrafficUsers(context.Background(), 2, 10, 200*1024)
	if err != nil {
		t.Fatalf("get daily low traffic users: %v", err)
	}
	if result["total"] != int64(1) || result["threshold_bytes"] != int64(200*1024) {
		t.Fatalf("unexpected result: %#v", result)
	}
	data, ok := result["data"].([]map[string]any)
	if !ok || len(data) != 1 || data[0]["traffic_bytes"] != int64(102400) {
		t.Fatalf("unexpected data: %#v", result["data"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

func TestGetConsecutiveLowTrafficUsersRequiresEveryDayAndReturnsDailyDetails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	expectSubscribeAccessSchema(mock)
	mock.ExpectQuery(`HAVING COUNT\(\*\) = \$4 AND MIN\(traffic_value\) > 0 AND MAX\(traffic_value\) <= \$3[\s\S]+SELECT COUNT\(\*\) FROM qualified`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), int64(200*1024), int64(3)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(int64(1)))
	mock.ExpectQuery(`HAVING COUNT\(\*\) = \$4 AND MIN\(traffic_value\) > 0 AND MAX\(traffic_value\) <= \$3[\s\S]+selected AS[\s\S]+LEFT JOIN LATERAL`).
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), int64(200*1024), int64(3), int64(20), int64(0)).
		WillReturnRows(sqlmock.NewRows([]string{"user_id", "email", "record_at", "traffic_bytes", "last_ip", "last_ua", "last_at"}).
			AddRow(int64(9), "demo@example.com", int64(100), int64(1024), "203.0.113.7", "Clash/1.0", int64(123)).
			AddRow(int64(9), "demo@example.com", int64(200), int64(2048), "203.0.113.7", "Clash/1.0", int64(123)).
			AddRow(int64(9), "demo@example.com", int64(300), int64(4096), "203.0.113.7", "Clash/1.0", int64(123)))

	result, err := (&DBService{db: db}).GetConsecutiveLowTrafficUsers(context.Background(), 1, 20, 200*1024, 3)
	if err != nil {
		t.Fatalf("get consecutive low traffic users: %v", err)
	}
	if result["total"] != int64(1) || result["days"] != int64(3) {
		t.Fatalf("unexpected result: %#v", result)
	}
	data, ok := result["data"].([]map[string]any)
	if !ok || len(data) != 1 {
		t.Fatalf("unexpected data: %#v", result["data"])
	}
	daily, ok := data[0]["daily_traffic"].([]map[string]any)
	if !ok || len(daily) != 3 || daily[2]["traffic_bytes"] != int64(4096) {
		t.Fatalf("unexpected daily details: %#v", data[0]["daily_traffic"])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

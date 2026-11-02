package nodeapi

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/ipgeo"
	"forest/go-api/internal/platform/postgres"
)

// Validate actual SQL, upgrade preservation and report-to-statistics flow in an
// isolated schema. The environment must point to a disposable test database.
func TestOnlineLocationsPostgresUpgradeAndReporting(t *testing.T) {
	dsn := os.Getenv("DNS_FAILOVER_TEST_DSN")
	if dsn == "" {
		t.Skip("dedicated PostgreSQL test DSN required")
	}
	root, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	schema := fmt.Sprintf("online_analytics_%d", time.Now().UnixNano())
	if _, err = root.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer root.Exec("DROP SCHEMA " + schema + " CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := db.ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	installer, err := os.ReadFile("../../../database/install.pgsql.sql")
	if err != nil {
		t.Fatal(err)
	}
	exec(string(installer))
	// Recreate the pre-feature state so the Go upgrade creates the new table.
	exec("DROP TABLE v2_user_online_location")
	now := time.Now().Unix()
	for i, age := range []int64{20, 40, 700, 90000, 700000} {
		exec(`INSERT INTO v2_user(id,email,password,uuid,token,t,created_at,updated_at) VALUES($1,$2,'password-fixture',$3,$4,$5,1,1)`, i+1, fmt.Sprintf("qa%d@example.test", i+1), fmt.Sprintf("uuid-%d", i+1), fmt.Sprintf("token-%d", i+1), now-age)
	}
	var before, after string
	if err = db.QueryRow(`SELECT jsonb_agg(to_jsonb(u) ORDER BY id)::text FROM v2_user u`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = postgres.EnsureOnlineLocationSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if err = db.QueryRow(`SELECT jsonb_agg(to_jsonb(u) ORDER BY id)::text FROM v2_user u`).Scan(&after); err != nil || before != after {
		t.Fatal("upgrade changed existing users", err)
	}
	var resolver ipgeo.Resolver = &locationTestResolver{locations: map[string]ipgeo.Location{
		"113.92.157.29": {Known: true, CountryCode: "CN", CountryName: "中国", ProvinceCode: "440000", ProvinceName: "广东", CityName: "深圳市"},
		"8.8.8.8":       {Known: true, CountryCode: "US", CountryName: "美国"},
	}}
	if dir := os.Getenv("IPGEO_TEST_DIR"); dir != "" {
		geo := ipgeo.New(dir)
		defer geo.Close()
		if geo.Status().Status != "ready" {
			t.Fatal("real geography databases not ready")
		}
		resolver = geo
	}
	nodes := NewDBService(config.Config{DeviceLimitMode: 1}, db, nil).WithOnlineGeoResolver(resolver)
	panel := admin.NewDBService(config.Config{}, db).WithOnlineGeoResolver(resolver)
	if err = nodes.ReportAlive(ctx, AliveReportRequest{NodeType: "vmess", NodeID: 7, Users: map[int64][]string{1: {"113.92.157.29:443_android", "113.92.157.29:443_ios"}, 2: {"10.0.0.1_ios"}}}); err != nil {
		t.Fatal(err)
	}
	stats, err := panel.GetOnlineStats(ctx)
	if err != nil || stats.CurrentOnline != 2 || stats.Unique24h != 3 || stats.Unique7d != 4 || stats.TotalUsers != 5 || stats.GeoLocatedUsers != 1 || stats.GeoUnknownUsers != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	if len(stats.ChinaCities) != 1 || stats.ChinaCities[0].Code != "深圳" || stats.ChinaCities[0].Users != 1 {
		t.Fatal(stats.ChinaCities)
	}
	users, err := panel.GetOnlineUsers(ctx, admin.OnlineUsersRequest{Scope: "city", ProvinceCode: "440000", City: "深圳市", Page: 1, PageSize: 1})
	if err != nil || users.Total != 1 || len(users.Users) != 1 || users.Users[0].ID != 1 {
		t.Fatal(users, err)
	}
	users, err = panel.GetOnlineUsers(ctx, admin.OnlineUsersRequest{Scope: "unknown", Page: 1, PageSize: 20})
	if err != nil || users.Total != 1 || users.Users[0].ID != 2 {
		t.Fatal(users, err)
	}
	users, err = panel.GetOnlineUsers(ctx, admin.OnlineUsersRequest{Scope: "all", Search: "QA1@example.test", Page: 2, PageSize: 1})
	if err != nil || users.Total != 1 || len(users.Users) != 0 {
		t.Fatal("search or out-of-range page", users, err)
	}
	// An invalid report cannot erase the last valid location or renew its age.
	exec(`UPDATE v2_user_online_location SET last_seen_at=$1 WHERE user_id=1`, now-86400)
	if err = nodes.ReportAlive(ctx, AliveReportRequest{NodeType: "vmess", NodeID: 7, Users: map[int64][]string{1: {"10.0.0.2"}}}); err != nil {
		t.Fatal(err)
	}
	var country string
	var seen int64
	if err = db.QueryRow(`SELECT country_code,last_seen_at FROM v2_user_online_location WHERE user_id=1`).Scan(&country, &seen); err != nil || country != "CN" || seen != now-86400 {
		t.Fatal(country, seen, err)
	}
	stats, err = panel.GetOnlineStats(ctx)
	if err != nil || stats.GeoLocatedUsers != 1 {
		t.Fatal("old valid location discarded", stats, err)
	}
	// The short-lived cache can repair a missing summary after an upgrade.
	exec(`DELETE FROM v2_user_online_location WHERE user_id=1`)
	if err = nodes.ReportAlive(ctx, AliveReportRequest{NodeType: "vmess", NodeID: 7, Users: map[int64][]string{1: {"8.8.8.8"}}}); err != nil {
		t.Fatal(err)
	}
	exec(`DELETE FROM v2_user_online_location WHERE user_id=1`)
	if err = nodes.ReconcileOnlineLocations(ctx); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT country_code FROM v2_user_online_location WHERE user_id=1`).Scan(&country); err != nil || country != "US" {
		t.Fatal(country, err)
	}
	if err = db.QueryRow(`SELECT jsonb_agg(to_jsonb(u) ORDER BY id)::text FROM v2_user u`).Scan(&after); err != nil || before != after {
		t.Fatal("alive analytics mutated user accounting", err)
	}
	var locationJSON string
	if err = db.QueryRow(`SELECT jsonb_agg(to_jsonb(l))::text FROM v2_user_online_location l`).Scan(&locationJSON); err != nil || strings.Contains(locationJSON, "8.8.8.8") || strings.Contains(locationJSON, "113.92.157.29") {
		t.Fatal("raw IP persisted in location summary", err)
	}
	exec(`DELETE FROM v2_user WHERE id=1`)
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM v2_user_online_location WHERE user_id=1`).Scan(&count); err != nil || count != 0 {
		t.Fatal("deleted account retained location", count, err)
	}
}

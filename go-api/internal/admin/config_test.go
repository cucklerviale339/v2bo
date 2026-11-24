package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cfgpkg "forest/go-api/internal/config"

	"github.com/DATA-DOG/go-sqlmock"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestBuildSMTPMessageAddsDeliverabilityHeaders(t *testing.T) {
	message := string(buildSMTPMessage("noreply@example.com", "Forest Mail", "user@example.net", "Subject", "Body"))

	if !strings.Contains(message, "\r\nDate: ") {
		t.Fatalf("expected date header, got %q", message)
	}
	if !strings.Contains(message, "\r\nMessage-ID: <") || !strings.Contains(message, "@example.com>") {
		t.Fatalf("expected message id header with sender domain, got %q", message)
	}
}

func TestDBServiceFetchConfigAndTemplates(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"invite_campaign_enable":        1,
		"invite_commission":             20,
		"commission_auto_check_minutes": 1440,
		"order_keep_days":               30,
		"mail_log_keep_days":            15,
		"log_keep_days":                 15,
		"stat_user_keep_days":           90,
		"stat_server_keep_days":         180,
		"auth_session_keep_days":        30,
		"runtime_kv_keep_days":          7,
		"failed_jobs_keep_days":         15,
		"commission_withdraw_method":    []string{"USDT", "支付宝"},
		"email_bulk_interval":           3,
		"email_whitelist_suffix":        []string{"qq.com"},
		"secure_path":                   "localadmin",
	})
	mustMkdirAll(t, filepath.Join(root, "resources", "views", "mail", "default"))
	mustMkdirAll(t, filepath.Join(root, "resources", "views", "mail", "classic"))

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{AdminPath: "localadmin"}}
	data, err := service.FetchConfig(context.Background(), "")
	if err != nil {
		t.Fatalf("fetch config: %v", err)
	}

	invite, ok := data["invite"].(map[string]any)
	if !ok {
		t.Fatalf("expected invite group, got %#v", data)
	}
	if invite["invite_campaign_enable"] != int64(1) {
		t.Fatalf("expected invite campaign enabled, got %#v", invite["invite_campaign_enable"])
	}
	if invite["commission_auto_check_minutes"] != int64(1440) {
		t.Fatalf("expected commission auto check minutes 1440, got %#v", invite["commission_auto_check_minutes"])
	}
	subscribe, ok := data["subscribe"].(map[string]any)
	if !ok {
		t.Fatalf("expected subscribe group, got %#v", data)
	}
	if subscribe["order_keep_days"] != int64(30) {
		t.Fatalf("expected order_keep_days 30, got %#v", subscribe["order_keep_days"])
	}
	if subscribe["mail_log_keep_days"] != int64(15) {
		t.Fatalf("expected mail_log_keep_days 15, got %#v", subscribe["mail_log_keep_days"])
	}
	if subscribe["log_keep_days"] != int64(15) {
		t.Fatalf("expected log_keep_days 15, got %#v", subscribe["log_keep_days"])
	}
	if subscribe["stat_user_keep_days"] != int64(90) {
		t.Fatalf("expected stat_user_keep_days 90, got %#v", subscribe["stat_user_keep_days"])
	}
	if subscribe["stat_server_keep_days"] != int64(180) {
		t.Fatalf("expected stat_server_keep_days 180, got %#v", subscribe["stat_server_keep_days"])
	}
	if subscribe["auth_session_keep_days"] != int64(30) {
		t.Fatalf("expected auth_session_keep_days 30, got %#v", subscribe["auth_session_keep_days"])
	}
	if subscribe["runtime_kv_keep_days"] != int64(7) {
		t.Fatalf("expected runtime_kv_keep_days 7, got %#v", subscribe["runtime_kv_keep_days"])
	}
	if subscribe["failed_jobs_keep_days"] != int64(15) {
		t.Fatalf("expected failed_jobs_keep_days 15, got %#v", subscribe["failed_jobs_keep_days"])
	}
	methods, ok := invite["commission_withdraw_method"].([]string)
	if !ok || len(methods) != 2 || methods[0] != "USDT" || methods[1] != "支付宝" {
		t.Fatalf("unexpected withdraw methods: %#v", invite["commission_withdraw_method"])
	}
	emailCfg, ok := data["email"].(map[string]any)
	if !ok {
		t.Fatalf("expected email group, got %#v", data)
	}
	if emailCfg["email_bulk_interval"] != int64(3) {
		t.Fatalf("unexpected email bulk interval: %#v", emailCfg["email_bulk_interval"])
	}

	emailTemplates, err := service.ListEmailTemplates(context.Background())
	if err != nil {
		t.Fatalf("list email templates: %v", err)
	}
	if len(emailTemplates) != 2 || emailTemplates[0] != "classic" || emailTemplates[1] != "default" {
		t.Fatalf("unexpected email templates: %#v", emailTemplates)
	}
}

func TestDBServiceTelegramAdminStatusShowsBindingAndWebhookURL(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"app_url":              "https://site.example",
		"telegram_webhook_url": "https://api.example",
		"telegram_bot_token":   "bot-token",
		"telegram_bot_enable":  1,
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT telegram_id FROM v2_user WHERE id = \$1 LIMIT 1`).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"telegram_id"}).AddRow(int64(12345)))

	service := &DBService{cfg: cfgpkg.Config{AppURL: "https://fallback.example"}, db: db}
	status, err := service.GetTelegramAdminStatus(context.Background(), 9)
	if err != nil {
		t.Fatalf("telegram status: %v", err)
	}
	if status.BotEnabled != true || status.TokenConfigured != true || status.AdminBound != true || status.TelegramID == nil || *status.TelegramID != 12345 {
		t.Fatalf("unexpected telegram status: %#v", status)
	}
	if status.WebhookURL != "https://api.example/api/v1/guest/telegram/webhook?access_token=30f9218d8b0b9633f4ed541cfa7089b5" {
		t.Fatalf("unexpected webhook url: %q", status.WebhookURL)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestValidateTelegramWebhookURLRejectsUnsupportedPort(t *testing.T) {
	err := validateTelegramWebhookURL("https://api.example:8080/api/v1/guest/telegram/webhook?access_token=abc")
	if err == nil || !strings.Contains(err.Error(), "当前端口是8080") {
		t.Fatalf("expected unsupported port error, got %v", err)
	}
}

func TestValidateTelegramWebhookURLAllowsTelegramPorts(t *testing.T) {
	for _, rawURL := range []string{
		"https://api.example/api/v1/guest/telegram/webhook?access_token=abc",
		"https://api.example:443/api/v1/guest/telegram/webhook?access_token=abc",
		"https://api.example:8443/api/v1/guest/telegram/webhook?access_token=abc",
	} {
		if err := validateTelegramWebhookURL(rawURL); err != nil {
			t.Fatalf("expected %s to be allowed, got %v", rawURL, err)
		}
	}
}

func TestTelegramAPIResultMapRedactsTokenInTransportErrors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp bot-token: i/o timeout")
	})}

	_, err := telegramAPIResultMap(client, "bot-token", "getMe", nil)
	if err == nil {
		t.Fatalf("expected transport error")
	}
	if strings.Contains(err.Error(), "bot-token") {
		t.Fatalf("expected token to be redacted, got %v", err)
	}
	if !strings.Contains(err.Error(), "请求Telegram失败") {
		t.Fatalf("expected telegram request context, got %v", err)
	}
}

func TestTelegramAPIResultMapReturnsTelegramDescription(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusBadRequest,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(`{"ok":false,"description":"Bad Request: bad webhook"}`)),
		}, nil
	})}

	_, err := telegramAPIResultMap(client, "bot-token", "setWebhook", map[string]string{"url": "https://api.example/webhook"})
	if err == nil || !strings.Contains(err.Error(), "Bad Request: bad webhook") {
		t.Fatalf("expected telegram description, got %v", err)
	}
}

func TestTelegramAPIResultMapAcceptsBooleanResult(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(`{"ok":true,"result":true,"description":"Webhook is already set"}`)),
		}, nil
	})}

	result, err := telegramAPIResultMap(client, "bot-token", "setWebhook", map[string]string{"url": "https://api.example/webhook"})
	if err != nil {
		t.Fatalf("expected boolean result to be accepted, got %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty result map, got %#v", result)
	}
}

func TestDBServiceSendTelegramTestMessageRequiresBoundAdmin(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"telegram_bot_token":  "bot-token",
		"telegram_bot_enable": 1,
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`SELECT telegram_id FROM v2_user WHERE id = \$1 LIMIT 1`).
		WithArgs(int64(9)).
		WillReturnRows(sqlmock.NewRows([]string{"telegram_id"}).AddRow(nil))

	service := &DBService{cfg: cfgpkg.Config{}, db: db}
	if _, err := service.SendTelegramTestMessage(context.Background(), 9); err == nil || err.Error() != "当前管理员未绑定Telegram，请先私聊机器人发送 /bind 订阅链接" {
		t.Fatalf("expected unbound telegram error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet sql expectations: %v", err)
	}
}

func TestDBServiceSaveConfigPersistsJSONValues(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"secure_path":                "localadmin",
		"commission_withdraw_method": []string{"USDT"},
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{AdminPath: "localadmin"}}
	ok, err := service.SaveConfig(context.Background(), map[string]any{
		"secure_path":                "newsecure",
		"deposit_bounus":             []any{"100:10"},
		"commission_withdraw_method": []any{"USDT", "支付宝"},
		"email_bulk_interval":        5,
		"mail_log_keep_days":         15,
		"stat_user_keep_days":        90,
	})
	if err != nil {
		t.Fatalf("save config: %v", err)
	}
	if !ok {
		t.Fatalf("expected save config success")
	}

	cfg, err := loadAdminConfigStore(adminConfigPath())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.stringValue("secure_path", "") != "newsecure" {
		t.Fatalf("expected secure path newsecure, got %q", cfg.stringValue("secure_path", ""))
	}
	bonus := cfg.stringSliceValue("deposit_bounus", nil)
	if len(bonus) != 1 || bonus[0] != "100:10" {
		t.Fatalf("unexpected deposit bonus: %#v", bonus)
	}
	methods := cfg.stringSliceValue("commission_withdraw_method", nil)
	if len(methods) != 2 || methods[0] != "USDT" || methods[1] != "支付宝" {
		t.Fatalf("unexpected withdraw methods after save: %#v", methods)
	}

	raw, err := os.ReadFile(filepath.Join(root, "config", "admin.json"))
	if err != nil {
		t.Fatalf("read written config: %v", err)
	}
	var written map[string]any
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatalf("decode written config json: %v", err)
	}
	if written["secure_path"] != "newsecure" {
		t.Fatalf("expected secure_path in json, got %#v", written["secure_path"])
	}
	if written["email_bulk_interval"] != "5" && written["email_bulk_interval"] != float64(5) {
		t.Fatalf("expected email_bulk_interval in json, got %#v", written["email_bulk_interval"])
	}
	if written["mail_log_keep_days"] != "15" && written["mail_log_keep_days"] != float64(15) {
		t.Fatalf("expected mail_log_keep_days in json, got %#v", written["mail_log_keep_days"])
	}
	if written["stat_user_keep_days"] != "90" && written["stat_user_keep_days"] != float64(90) {
		t.Fatalf("expected stat_user_keep_days in json, got %#v", written["stat_user_keep_days"])
	}
}

func TestDBServiceSaveConfigRejectsUnknownKeys(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"secure_path": "localadmin",
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{AdminPath: "localadmin"}}
	if _, err := service.SaveConfig(context.Background(), map[string]any{
		"app_name":    "Forest",
		"unknown_key": "bad",
		"another_key": 1,
	}); err == nil || !strings.Contains(err.Error(), "unsupported config key") {
		t.Fatalf("expected unsupported config key error, got %v", err)
	}

	cfg, err := loadAdminConfigStore(adminConfigPath())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if _, exists := cfg.values["unknown_key"]; exists {
		t.Fatalf("unknown key should not be persisted")
	}
}

func TestDBServiceSaveConfigKeepsExistingSensitiveValueWhenSubmittedEmpty(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"email_password":     "smtp-secret",
		"telegram_bot_token": "bot-secret",
		"server_token":       "server-secret-long-enough",
		"app_name":           "Forest",
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{AdminPath: "localadmin"}}
	if _, err := service.SaveConfig(context.Background(), map[string]any{
		"email_password":     "",
		"telegram_bot_token": " ",
		"server_token":       "",
		"app_name":           "Poxiao",
	}); err != nil {
		t.Fatalf("save config: %v", err)
	}

	cfg, err := loadAdminConfigStore(adminConfigPath())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.stringValue("email_password", "") != "smtp-secret" {
		t.Fatalf("expected existing email password preserved, got %q", cfg.stringValue("email_password", ""))
	}
	if cfg.stringValue("telegram_bot_token", "") != "bot-secret" {
		t.Fatalf("expected existing telegram token preserved, got %q", cfg.stringValue("telegram_bot_token", ""))
	}
	if cfg.stringValue("server_token", "") != "server-secret-long-enough" {
		t.Fatalf("expected existing server token preserved, got %q", cfg.stringValue("server_token", ""))
	}
	if cfg.stringValue("app_name", "") != "Poxiao" {
		t.Fatalf("expected non-sensitive field saved, got %q", cfg.stringValue("app_name", ""))
	}
}

func TestDBServiceSaveConfigRejectsPlaceholderSiteValues(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"app_name":      "破晓",
		"app_url":       "https://xn--1jvw11b.com",
		"logo":          "https://new.mao2api.com/assets/brand/logo-poxiao.png",
		"subscribe_url": "https://guangmingyinpin.poxiao888.com",
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{AdminPath: "localadmin"}}
	badCases := []map[string]any{
		{"app_name": "1"},
		{"app_description": "1"},
		{"app_url": "https://1"},
		{"logo": "https://1"},
		{"subscribe_url": "https://1"},
	}
	for _, values := range badCases {
		if _, err := service.SaveConfig(context.Background(), values); err == nil {
			t.Fatalf("expected placeholder config rejected for %#v", values)
		}
	}

	cfg, err := loadAdminConfigStore(adminConfigPath())
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if cfg.stringValue("app_name", "") != "破晓" {
		t.Fatalf("expected app_name preserved, got %q", cfg.stringValue("app_name", ""))
	}
	if cfg.stringValue("app_url", "") != "https://xn--1jvw11b.com" {
		t.Fatalf("expected app_url preserved, got %q", cfg.stringValue("app_url", ""))
	}
	if _, err := service.SaveConfig(context.Background(), map[string]any{
		"app_url":       "https://poxiao688.com",
		"logo":          "https://new.mao2api.com/assets/brand/logo-poxiao.png",
		"subscribe_url": "https://guangmingyinpin.poxiao888.com,https://poxiao688.com",
	}); err != nil {
		t.Fatalf("expected valid site urls accepted: %v", err)
	}
}

func TestDBServiceSaveConfigReloadsRuntimeConfig(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"secure_path":                   "localadmin",
		"allow_new_period":              0,
		"reset_traffic_method":          0,
		"commission_auto_check_minutes": 4320,
		"order_keep_days":               0,
		"mail_log_keep_days":            0,
		"log_keep_days":                 0,
		"stat_user_keep_days":           0,
		"stat_server_keep_days":         0,
		"auth_session_keep_days":        0,
		"runtime_kv_keep_days":          0,
		"failed_jobs_keep_days":         0,
	})
	mustMkdirAll(t, filepath.Join(root, "go-api"))

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	prevWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	defer func() { _ = os.Chdir(prevWD) }()
	if err := os.Chdir(filepath.Join(root, "go-api")); err != nil {
		t.Fatalf("chdir work dir: %v", err)
	}

	t.Setenv("ALLOW_NEW_PERIOD", "")
	t.Setenv("RESET_TRAFFIC_METHOD", "")

	cfg := cfgpkg.Load()
	runtimeState := cfgpkg.NewRuntimeState(cfg)
	service := (&DBService{cfg: cfg}).WithRuntimeConfig(runtimeState)

	if runtimeState.Current().AllowNewPeriod {
		t.Fatalf("expected allow_new_period disabled before save")
	}
	if runtimeState.Current().ResetTrafficMethod != 0 {
		t.Fatalf("expected reset_traffic_method=0 before save, got %d", runtimeState.Current().ResetTrafficMethod)
	}
	if runtimeState.Current().CommissionAutoCheckMinutes != 4320 {
		t.Fatalf("expected commission_auto_check_minutes=4320 before save, got %d", runtimeState.Current().CommissionAutoCheckMinutes)
	}
	if runtimeState.Current().OrderKeepDays != 0 {
		t.Fatalf("expected order_keep_days=0 before save, got %d", runtimeState.Current().OrderKeepDays)
	}
	if runtimeState.Current().MailLogKeepDays != 0 {
		t.Fatalf("expected mail_log_keep_days=0 before save, got %d", runtimeState.Current().MailLogKeepDays)
	}
	if runtimeState.Current().LogKeepDays != 0 {
		t.Fatalf("expected log_keep_days=0 before save, got %d", runtimeState.Current().LogKeepDays)
	}
	if runtimeState.Current().StatUserKeepDays != 0 {
		t.Fatalf("expected stat_user_keep_days=0 before save, got %d", runtimeState.Current().StatUserKeepDays)
	}
	if runtimeState.Current().StatServerKeepDays != 0 {
		t.Fatalf("expected stat_server_keep_days=0 before save, got %d", runtimeState.Current().StatServerKeepDays)
	}
	if runtimeState.Current().AuthSessionKeepDays != 0 {
		t.Fatalf("expected auth_session_keep_days=0 before save, got %d", runtimeState.Current().AuthSessionKeepDays)
	}
	if runtimeState.Current().RuntimeKVKeepDays != 0 {
		t.Fatalf("expected runtime_kv_keep_days=0 before save, got %d", runtimeState.Current().RuntimeKVKeepDays)
	}
	if runtimeState.Current().FailedJobsKeepDays != 0 {
		t.Fatalf("expected failed_jobs_keep_days=0 before save, got %d", runtimeState.Current().FailedJobsKeepDays)
	}

	ok, err := service.SaveConfig(context.Background(), map[string]any{
		"allow_new_period":              1,
		"reset_traffic_method":          4,
		"new_order_event_id":            1,
		"renew_order_event_id":          1,
		"change_order_event_id":         1,
		"commission_auto_check_minutes": 90,
		"order_keep_days":               45,
		"mail_log_keep_days":            15,
		"log_keep_days":                 15,
		"stat_user_keep_days":           90,
		"stat_server_keep_days":         180,
		"auth_session_keep_days":        30,
		"runtime_kv_keep_days":          7,
		"failed_jobs_keep_days":         15,
	})
	if err != nil {
		t.Fatalf("save config: %v", err)
	}
	if !ok {
		t.Fatalf("expected save config success")
	}

	if !runtimeState.Current().AllowNewPeriod {
		t.Fatalf("expected allow_new_period enabled after save")
	}
	if runtimeState.Current().ResetTrafficMethod != 4 {
		t.Fatalf("expected reset_traffic_method=4 after save, got %d", runtimeState.Current().ResetTrafficMethod)
	}
	if runtimeState.Current().CommissionAutoCheckMinutes != 90 {
		t.Fatalf("expected commission_auto_check_minutes=90 after save, got %d", runtimeState.Current().CommissionAutoCheckMinutes)
	}
	if runtimeState.Current().OrderKeepDays != 45 {
		t.Fatalf("expected order_keep_days=45 after save, got %d", runtimeState.Current().OrderKeepDays)
	}
	if runtimeState.Current().MailLogKeepDays != 15 {
		t.Fatalf("expected mail_log_keep_days=15 after save, got %d", runtimeState.Current().MailLogKeepDays)
	}
	if runtimeState.Current().LogKeepDays != 15 {
		t.Fatalf("expected log_keep_days=15 after save, got %d", runtimeState.Current().LogKeepDays)
	}
	if runtimeState.Current().StatUserKeepDays != 90 {
		t.Fatalf("expected stat_user_keep_days=90 after save, got %d", runtimeState.Current().StatUserKeepDays)
	}
	if runtimeState.Current().StatServerKeepDays != 180 {
		t.Fatalf("expected stat_server_keep_days=180 after save, got %d", runtimeState.Current().StatServerKeepDays)
	}
	if runtimeState.Current().AuthSessionKeepDays != 30 {
		t.Fatalf("expected auth_session_keep_days=30 after save, got %d", runtimeState.Current().AuthSessionKeepDays)
	}
	if runtimeState.Current().RuntimeKVKeepDays != 7 {
		t.Fatalf("expected runtime_kv_keep_days=7 after save, got %d", runtimeState.Current().RuntimeKVKeepDays)
	}
	if runtimeState.Current().FailedJobsKeepDays != 15 {
		t.Fatalf("expected failed_jobs_keep_days=15 after save, got %d", runtimeState.Current().FailedJobsKeepDays)
	}
	updated := runtimeState.CurrentConfig()
	if updated.NewOrderEventID != 1 || updated.RenewOrderEventID != 1 || updated.ChangeOrderEventID != 1 {
		t.Fatalf("order completion actions not reloaded: %d %d %d", updated.NewOrderEventID, updated.RenewOrderEventID, updated.ChangeOrderEventID)
	}
	if _, err := service.SaveConfig(context.Background(), map[string]any{"renew_order_event_id": 2}); !errors.Is(err, ErrInvalidOrderCompletionAction) {
		t.Fatalf("expected invalid order completion action error, got %v", err)
	}
	if runtimeState.CurrentConfig().RenewOrderEventID != 1 {
		t.Fatal("invalid input changed the saved action")
	}
}

func TestLoadBulkMailConfigFallsBackToAppNameForFromName(t *testing.T) {
	root := t.TempDir()
	writeAdminJSONFixture(t, root, map[string]any{
		"app_name":           "Forest",
		"app_url":            "https://forest.example.com",
		"email_host":         "smtp.example.com",
		"email_port":         2525,
		"email_from_address": "noreply@example.com",
		"email_template":     "forest-v2",
	})

	oldRoot := adminProjectRoot
	adminProjectRoot = root
	defer func() { adminProjectRoot = oldRoot }()

	service := &DBService{cfg: cfgpkg.Config{
		AppName:         "forest",
		AppURL:          "http://localhost",
		MailHost:        "127.0.0.1",
		MailPort:        25,
		MailFromAddress: "env@example.com",
		MailFromName:    "forest",
	}}
	mailCfg, err := service.loadBulkMailConfig()
	if err != nil {
		t.Fatalf("load bulk mail config: %v", err)
	}
	if mailCfg.fromName != "Forest" {
		t.Fatalf("expected fromName Forest, got %q", mailCfg.fromName)
	}
	if mailCfg.appURL != "https://forest.example.com" {
		t.Fatalf("expected appURL from admin.json, got %q", mailCfg.appURL)
	}
	if mailCfg.template != "forest-v2" {
		t.Fatalf("expected template forest-v2, got %q", mailCfg.template)
	}
}

func writeAdminJSONFixture(t *testing.T, root string, values map[string]any) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(root, "config"))
	raw, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		t.Fatalf("marshal admin json fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "config", "admin.json"), raw, 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
}

func writeAdminLegacyConfigFixture(t *testing.T, root, content string) {
	t.Helper()
	mustMkdirAll(t, filepath.Join(root, "config"))
	if err := os.WriteFile(filepath.Join(root, "config", "site.php"), []byte(content), 0o644); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

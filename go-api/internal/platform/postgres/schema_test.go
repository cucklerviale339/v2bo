package postgres

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestEnsureClientEntrySchemaCreatesMissingTablesAndColumns(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group_member`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group_ip`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	for _, item := range []struct {
		table  string
		column string
		stmt   string
	}{
		{"v2_client_entry_group", "remote_enabled", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_enabled SMALLINT NOT NULL DEFAULT 0`},
		{"v2_client_entry_group", "remote_host", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_host varchar\(255\) NOT NULL DEFAULT ''`},
		{"v2_client_entry_group", "remote_ssh_port", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_ssh_port INTEGER NOT NULL DEFAULT 22`},
		{"v2_client_entry_group", "remote_ssh_user", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_ssh_user varchar\(255\) NOT NULL DEFAULT ''`},
		{"v2_client_entry_group", "remote_ssh_password", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_ssh_password text NOT NULL DEFAULT ''`},
		{"v2_client_entry_group", "remote_group_ref", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_group_ref varchar\(255\) NOT NULL DEFAULT ''`},
		{"v2_client_entry_group", "remote_exclude_names", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_exclude_names text NOT NULL DEFAULT '\[\]'`},
		{"v2_client_entry_group", "remote_refresh_sec", `ALTER TABLE v2_client_entry_group ADD COLUMN remote_refresh_sec INTEGER NOT NULL DEFAULT 300`},
	} {
		mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
			WithArgs(item.table, item.column).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
		mock.ExpectExec(item.stmt).
			WillReturnResult(sqlmock.NewResult(0, 0))
	}

	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_client_entry_group_member_group ON v2_client_entry_group_member\(entry_group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_client_entry_group_ip_group ON v2_client_entry_group_ip\(entry_group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := EnsureClientEntrySchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureClientEntrySchema: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestEnsureClientEntrySchemaSkipsExistingColumns(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group_member`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_client_entry_group_ip`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	for _, item := range []struct {
		table  string
		column string
	}{
		{"v2_client_entry_group", "remote_enabled"},
		{"v2_client_entry_group", "remote_host"},
		{"v2_client_entry_group", "remote_ssh_port"},
		{"v2_client_entry_group", "remote_ssh_user"},
		{"v2_client_entry_group", "remote_ssh_password"},
		{"v2_client_entry_group", "remote_group_ref"},
		{"v2_client_entry_group", "remote_exclude_names"},
		{"v2_client_entry_group", "remote_refresh_sec"},
	} {
		mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
			WithArgs(item.table, item.column).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
	}

	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_client_entry_group_member_group ON v2_client_entry_group_member\(entry_group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_client_entry_group_ip_group ON v2_client_entry_group_ip\(entry_group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := EnsureClientEntrySchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureClientEntrySchema: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

func TestEnsureNodeAddressSchemaAddsRuleColumns(t *testing.T) {
	t.Parallel()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_node_address_group`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_node_address_rule`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_node_address_binding`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE TABLE IF NOT EXISTS v2_insider_rule`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	for _, tableName := range []string{"v2_node_address_group", "v2_node_address_rule"} {
		mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
			WithArgs(tableName, "enabled").
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))
		mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
			WithArgs(tableName, "show").
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	}

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
		WithArgs("v2_node_address_rule", "match_user_id_ranges").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`ALTER TABLE v2_node_address_rule ADD COLUMN match_user_id_ranges text NOT NULL DEFAULT '\[\]'`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
		WithArgs("v2_node_address_rule", "extra_nodes").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`ALTER TABLE v2_node_address_rule ADD COLUMN extra_nodes text NOT NULL DEFAULT '\[\]'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT EXISTS \(\s*SELECT 1 FROM information_schema.columns`).
		WithArgs("v2_node_address_rule", "extra_nodes_position").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectExec(`ALTER TABLE v2_node_address_rule ADD COLUMN extra_nodes_position varchar\(16\) NOT NULL DEFAULT 'replace'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`UPDATE v2_node_address_rule SET extra_nodes_position = 'replace' WHERE extra_nodes_position = 'after'`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`ALTER TABLE v2_node_address_rule ALTER COLUMN extra_nodes_position SET DEFAULT 'replace'`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_node_address_rule_group ON v2_node_address_rule\(group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_node_address_binding_group ON v2_node_address_binding\(address_group_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_node_address_binding_server ON v2_node_address_binding\(server_type, server_id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`CREATE INDEX IF NOT EXISTS idx_v2_insider_rule_sort ON v2_insider_rule\(sort, id\)`).
		WillReturnResult(sqlmock.NewResult(0, 0))

	if err := EnsureNodeAddressSchema(context.Background(), db); err != nil {
		t.Fatalf("EnsureNodeAddressSchema: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("sql expectations: %v", err)
	}
}

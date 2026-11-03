package postgres

// Kept with the address schema so catalog reads and subscription dispatch never
// depend on an administrator having opened the new page first.
var DispatchInvestigationSchema = []string{
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_settings(id INTEGER PRIMARY KEY CHECK(id=1),enabled BOOLEAN NOT NULL DEFAULT FALSE,armed_at BIGINT NOT NULL DEFAULT 0,revision BIGINT NOT NULL DEFAULT 1,entry_window_minutes INTEGER NOT NULL DEFAULT 20 CHECK(entry_window_minutes BETWEEN 1 AND 10080),global_window_minutes INTEGER NOT NULL DEFAULT 60 CHECK(global_window_minutes BETWEEN 1 AND 10080),global_max INTEGER NOT NULL DEFAULT 3 CHECK(global_max BETWEEN 1 AND 100))`,
	`INSERT INTO v2_dispatch_investigation_settings(id) VALUES(1) ON CONFLICT DO NOTHING`,
	`ALTER TABLE v2_dispatch_investigation_settings ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'all' CHECK(scope IN('all','multi_range'))`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_group(id BIGSERIAL PRIMARY KEY,root_id BIGINT NOT NULL DEFAULT 0,parent_id BIGINT NOT NULL DEFAULT 0,legacy_root_id BIGINT NOT NULL DEFAULT 0,name TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN('candidate','observation','confirmed','recent')),host TEXT NOT NULL,monitor_id BIGINT NOT NULL,active BOOLEAN NOT NULL DEFAULT TRUE,manual_only BOOLEAN NOT NULL DEFAULT FALSE,revision BIGINT NOT NULL DEFAULT 1,generation BIGINT NOT NULL DEFAULT 1,epoch_at BIGINT NOT NULL,ready_at BIGINT NOT NULL DEFAULT 0,config_key TEXT NOT NULL DEFAULT '',reason TEXT NOT NULL DEFAULT '',no_pull_count INTEGER NOT NULL DEFAULT 0,created_at BIGINT NOT NULL)`,
	`DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='v2_dispatch_investigation_group'::regclass AND conname='v2_dispatch_investigation_group_kind_check' AND pg_get_constraintdef(oid) NOT LIKE '%recent%') THEN ALTER TABLE v2_dispatch_investigation_group DROP CONSTRAINT v2_dispatch_investigation_group_kind_check; ALTER TABLE v2_dispatch_investigation_group ADD CONSTRAINT v2_dispatch_investigation_group_kind_check CHECK(kind IN('candidate','observation','confirmed','recent')); END IF; END $$`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_investigation_live ON v2_dispatch_investigation_group(active,monitor_id)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_confirmation(group_id BIGINT PRIMARY KEY REFERENCES v2_dispatch_investigation_group(id),generation BIGINT NOT NULL,confirmed_at BIGINT NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_member(root_id BIGINT NOT NULL,origin_host TEXT NOT NULL,user_id BIGINT NOT NULL,group_id BIGINT NOT NULL REFERENCES v2_dispatch_investigation_group(id),PRIMARY KEY(root_id,origin_host,user_id))`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_investigation_member_group ON v2_dispatch_investigation_member(group_id,user_id)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_investigation_member_user ON v2_dispatch_investigation_member(user_id,origin_host)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_delivery(group_id BIGINT NOT NULL,generation BIGINT NOT NULL,user_id BIGINT NOT NULL,delivered_at BIGINT NOT NULL,PRIMARY KEY(group_id,generation,user_id,delivered_at))`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_dispatch_investigation_delivery_user ON v2_dispatch_investigation_delivery(group_id,generation,user_id)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_delivery_recent(group_id BIGINT NOT NULL,generation BIGINT NOT NULL,user_id BIGINT NOT NULL,delivered_at BIGINT NOT NULL,PRIMARY KEY(group_id,generation,user_id,delivered_at))`,
	`ALTER TABLE v2_dispatch_investigation_settings ADD COLUMN IF NOT EXISTS recent_receipts_started_at BIGINT NOT NULL DEFAULT 0`,
	// Old receipts only contain the first pull. Start a complete observation
	// round once, preserving all memberships, assignments, switches and limits.
	`WITH upgraded AS (UPDATE v2_dispatch_investigation_settings SET recent_receipts_started_at=EXTRACT(EPOCH FROM clock_timestamp())::bigint WHERE id=1 AND recent_receipts_started_at=0 RETURNING recent_receipts_started_at) UPDATE v2_dispatch_investigation_group SET generation=generation+1,epoch_at=upgraded.recent_receipts_started_at,ready_at=0,revision=revision+1,reason='开始记录120分钟拉取证据，等待入口确认正常' FROM upgraded WHERE active AND NOT manual_only`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_event(id BIGSERIAL PRIMARY KEY,root_id BIGINT NOT NULL,group_id BIGINT NOT NULL,kind TEXT NOT NULL,first_failure_at BIGINT NOT NULL DEFAULT 0,created_at BIGINT NOT NULL,payload JSONB NOT NULL)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_investigation_event_time ON v2_dispatch_investigation_event(created_at DESC,id DESC)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_investigation_event_family ON v2_dispatch_investigation_event(root_id,created_at DESC)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_investigation_health(id INTEGER PRIMARY KEY CHECK(id=1),delivery_failure_at BIGINT NOT NULL DEFAULT 0)`,
	`INSERT INTO v2_dispatch_investigation_health(id) VALUES(1) ON CONFLICT DO NOTHING`,
}

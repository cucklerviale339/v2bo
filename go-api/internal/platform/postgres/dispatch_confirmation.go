package postgres

var dispatchConfirmationSchema = []string{
	`ALTER TABLE v2_dispatch_investigation_group ADD COLUMN IF NOT EXISTS confirmation_proof JSONB NOT NULL DEFAULT '{}'`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_risk_case(event_id BIGINT PRIMARY KEY REFERENCES v2_dispatch_investigation_event(id),created_at BIGINT NOT NULL,resolved_event_id BIGINT NOT NULL DEFAULT 0,resolved_at BIGINT NOT NULL DEFAULT 0)`,
	`CREATE TABLE IF NOT EXISTS v2_dispatch_risk_member(event_id BIGINT NOT NULL REFERENCES v2_dispatch_risk_case(event_id),user_id BIGINT NOT NULL,PRIMARY KEY(event_id,user_id))`,
	`ALTER TABLE v2_dispatch_risk_member ADD COLUMN IF NOT EXISTS group_id BIGINT NOT NULL DEFAULT 0`,
	`ALTER TABLE v2_dispatch_risk_member ADD COLUMN IF NOT EXISTS cleared_event_id BIGINT NOT NULL DEFAULT 0`,
	`ALTER TABLE v2_dispatch_risk_member ADD COLUMN IF NOT EXISTS cleared_at BIGINT NOT NULL DEFAULT 0`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_risk_user ON v2_dispatch_risk_member(user_id,event_id)`,
	`CREATE INDEX IF NOT EXISTS idx_dispatch_confirmation_user ON v2_dispatch_investigation_event((payload->'confirmation'->>'user_id')) WHERE payload->'confirmation'->>'version'='1'`,
	// Legacy labels did not record a sole-recipient healthy-round proof. Keep
	// the routing and original audit; remove the unsupported label. Only an
	// untouched automatic singleton may automatically resume address recovery.
	`DO $$ BEGIN IF to_regclass('v2_dispatch_monitor') IS NOT NULL THEN WITH birth AS (
SELECT DISTINCT ON(g.id) g.id,p,e.payload
FROM v2_dispatch_investigation_group g JOIN v2_dispatch_investigation_event e ON e.group_id=g.parent_id
CROSS JOIN LATERAL jsonb_array_elements(COALESCE(e.payload->'partitions','[]')) p
WHERE e.kind IN('filtered','bisected','whitelist_bisected') AND p->>'group_id'=g.id::text
AND e.created_at BETWEEN g.created_at-1 AND g.created_at+1 ORDER BY g.id,e.id DESC), eligible AS (
SELECT b.*,(g.active AND g.manual_only AND g.revision=1 AND g.generation=1 AND g.policy='smart'
AND g.route_scope='business' AND g.lifecycle_role='ordinary' AND g.host=b.p->>'host'
AND jsonb_array_length(COALESCE(b.p->'user_ids','[]'))=1
AND EXISTS(SELECT 1 FROM v2_dispatch_monitor m WHERE m.id=g.monitor_id AND m.host=g.host AND NOT COALESCE((to_jsonb(m)->>'deleted')::boolean,FALSE))
AND EXISTS(SELECT 1 FROM v2_dispatch_investigation_member a JOIN v2_user u ON u.id=a.user_id WHERE a.group_id=g.id AND a.user_id::text=b.p->'user_ids'->>0)
AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_member a WHERE a.group_id=g.id AND a.user_id::text<>b.p->'user_ids'->>0)
AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_event x WHERE x.group_id=g.id AND x.kind IN('edited','confirmed_entry','members_moved','members_admitted'))) AS resume
FROM birth b JOIN v2_dispatch_investigation_group g ON g.id=b.id), corrected AS (
UPDATE v2_dispatch_investigation_group g SET
kind=CASE WHEN (b.payload->'unpulled_ids') @> (b.p->'user_ids') THEN 'observation' WHEN (b.payload->'recent_ids') @> (b.p->'user_ids') THEN 'recent' ELSE 'candidate' END,
name=CASE WHEN g.name='实锤内鬼' THEN CASE WHEN (b.payload->'unpulled_ids') @> (b.p->'user_ids') THEN '观察' WHEN (b.payload->'recent_ids') @> (b.p->'user_ids') THEN '120分钟' ELSE '卧底' END ELSE g.name END,
manual_only=CASE WHEN b.resume THEN FALSE ELSE g.manual_only END,
observation_repair_pending=b.resume,
revision=revision+1,reason='历史单人标签缺少入口本轮唯一拉取者的完整证据，已撤销实锤标记'
FROM eligible b WHERE g.id=b.id AND g.kind='confirmed' AND g.confirmation_proof='{}'::jsonb
RETURNING g.id,g.root_id,g.host,g.active)
INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload)
SELECT root_id,id,'confirmation_corrected',EXTRACT(EPOCH FROM clock_timestamp())::bigint,jsonb_build_object('host',host,'reason','单人分组不等于实锤；原审计保留，当前下发暂不改变') FROM corrected; END IF; END $$`,
	// Unknown legacy labels also cannot be used as proof, but absent a birth
	// roster no automatic routing or manual-policy change is justified.
	`WITH corrected AS (UPDATE v2_dispatch_investigation_group SET kind='candidate',name=CASE WHEN name='实锤内鬼' THEN '卧底' ELSE name END,revision=revision+1,reason='历史实锤缺少可验证证据，保留原入口及人工策略待复核' WHERE kind='confirmed' AND confirmation_proof='{}'::jsonb RETURNING id,root_id,host)
INSERT INTO v2_dispatch_investigation_event(root_id,group_id,kind,created_at,payload) SELECT root_id,id,'confirmation_corrected',EXTRACT(EPOCH FROM clock_timestamp())::bigint,jsonb_build_object('host',host,'reason','历史证据不足，撤销实锤标记，保留原下发及人工策略') FROM corrected`,
	`UPDATE v2_dispatch_investigation_group g SET manual_only=FALSE,revision=revision+1,reason='单人入口按健康基线及实际拉取证据观察'
WHERE g.active AND g.kind='candidate' AND g.parent_id=0 AND g.manual_only AND g.reason='单人组，仅人工操作'
AND g.policy='smart' AND NOT EXISTS(SELECT 1 FROM v2_dispatch_investigation_event e WHERE e.group_id=g.id AND e.kind IN('edited','confirmed_entry'))`,
}

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	usersvc "forest/go-api/internal/user"
)

func TestPostgresDispatchAccountIDsOverlapsAndFreshValidation(t *testing.T) {
	f := newInvestigationIntegration(t)
	entry := usersvc.DispatchEntry{Host: "range.example", UserIDs: []string{"11", "11", "999999", "bad"}, UserIDRanges: []string{"10-14", "12-17", "bad", "17-9223372036854775807"}}
	want := []int64{11, 12, 13, 14, 15, 16, 17, 42, 150}
	ids, err := usersvc.DispatchAccountIDs(f.ctx, f.db, entry)
	if err != nil || !reflect.DeepEqual(ids, want) {
		t.Fatal("overlapping ranges must return existing IDs once, in order", ids, err)
	}
	empty, err := usersvc.DispatchAccountIDs(f.ctx, f.db, usersvc.DispatchEntry{})
	if err != nil || len(empty) != 0 {
		t.Fatal(empty, err)
	}
	accounts := newInvestigationDispatchAccounts(f.db)
	if _, err = accounts.load(f.ctx, entry); err != nil {
		t.Fatal(err)
	}
	f.exec(`DELETE FROM v2_user WHERE id=11`)
	cached, err := accounts.load(f.ctx, entry)
	if err != nil || !reflect.DeepEqual(cached, want) {
		t.Fatal("planning phase did not reuse its snapshot", cached, err)
	}
	fresh, err := newInvestigationDispatchAccounts(f.db).load(f.ctx, entry)
	if err != nil || !reflect.DeepEqual(fresh, []int64{12, 13, 14, 15, 16, 17, 42, 150}) {
		t.Fatal("commit phase reused deleted-account membership", fresh, err)
	}
}

func TestPostgresInvestigationDeadlineStatusRollbackAndRetry(t *testing.T) {
	f := newInvestigationIntegration(t)
	f.pool("192.0.2.211", "192.0.2.212")
	g := f.group("range.example")
	f.outage(g, []int64{11, 12, 13})
	g = f.group(g.Host)
	before := f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent", "v2_node_address_rule", "v2_insider_rule", "v2_dispatch_monitor", "v2_dispatch_check_target")
	// Stall only the attempted child creation, after evidence and allocation
	// planning. A real deadline must roll back the entire attempted move.
	f.exec(`CREATE FUNCTION stall_investigation_child() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$;
CREATE TRIGGER stall_investigation_child BEFORE INSERT ON v2_dispatch_investigation_group FOR EACH ROW EXECUTE FUNCTION stall_investigation_child()`)
	ctx, cancel := context.WithTimeout(f.ctx, 700*time.Millisecond)
	err := f.s.processInvestigationAction(ctx, g.ID, 0, false)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expected bounded action deadline", err)
	}
	after := f.group(g.Host)
	if after.Reason != investigationTimeoutReason || after.Generation != g.Generation || after.EpochAt != g.EpochAt || after.Revision != g.Revision || after.ReadyAt != g.ReadyAt || !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_member", "v2_dispatch_investigation_delivery", "v2_dispatch_investigation_delivery_recent", "v2_node_address_rule", "v2_insider_rule", "v2_dispatch_monitor", "v2_dispatch_check_target")) {
		t.Fatal("timeout lost evidence, changed delivery, or retained misleading status", after)
	}
	f.exec(`DROP TRIGGER stall_investigation_child ON v2_dispatch_investigation_group`)
	f.execProcess(g.ID)
	if f.successfulEvents() != 1 {
		t.Fatal("automatic retry did not complete the original incident", f.groups())
	}
}

func TestPostgresInvestigationTimeoutStatusDoesNotOverwriteNewerGroup(t *testing.T) {
	for _, change := range []string{
		`UPDATE v2_dispatch_investigation_group SET revision=revision+1,name='manual edit' WHERE id=$1`,
		`UPDATE v2_dispatch_investigation_group SET generation=generation+1 WHERE id=$1`,
		`UPDATE v2_dispatch_investigation_group SET reason='newer result' WHERE id=$1`,
	} {
		t.Run(change, func(t *testing.T) {
			f := newInvestigationIntegration(t)
			g := f.group("range.example")
			f.exec(change, g.ID)
			before := f.snapshot("v2_dispatch_investigation_group")
			ctx, cancel := context.WithCancel(f.ctx)
			cancel()
			if err := f.s.recordInvestigationTimeout(ctx, g); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, f.snapshot("v2_dispatch_investigation_group")) {
				t.Fatal("timeout overwrote newer group data")
			}
		})
	}
}

func TestPostgresInvestigationLargeFragmentedOutageWithinBudget(t *testing.T) {
	f := newInvestigationIntegration(t)
	g := f.group("range.example")
	f.exec(`INSERT INTO v2_user(id,email,password,uuid,token,group_id,plan_id,transfer_enable,created_at,updated_at)
SELECT id,'fragment-'||id||'@example.test','hash',lpad(id::text,36,'0'),lpad(id::text,32,'0'),1,1,1000000,1,1 FROM generate_series(1000,16999) id`)
	f.exec(`DELETE FROM v2_dispatch_investigation_member WHERE group_id=$1`, g.ID)
	f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id)
SELECT $1,'origin.example',1000+(n/9)*20+n%9,$2 FROM generate_series(0,6152) n`, g.RootID, g.ID)
	f.exec(`UPDATE v2_node_address_rule SET host='origin.example',match_user_ids='[]',match_user_id_ranges='["1000-16999"]' WHERE host=$1`, g.Host)
	for i := 0; i < 3; i++ {
		host := fmt.Sprintf("sibling-%d.example", i)
		var id int64
		if err := f.db.QueryRow(`INSERT INTO v2_dispatch_investigation_group(root_id,parent_id,name,kind,host,monitor_id,epoch_at,created_at)
VALUES($1,$2,'sibling','candidate',$3,$5,$4,$4) RETURNING id`, g.RootID, g.ID, host, time.Now().Unix()-1000, g.MonitorID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		f.exec(`INSERT INTO v2_dispatch_investigation_member(root_id,origin_host,user_id,group_id)
SELECT $1,'origin.example',15000+5*n+$3::bigint,$2 FROM generate_series(0,399) n`, g.RootID, id, i)
		f.save(host, f.pid)
		f.exec(`UPDATE v2_dispatch_investigation_group SET monitor_id=(SELECT id FROM v2_dispatch_monitor WHERE host=$2) WHERE id=$1`, id, host)
	}
	f.exec(`UPDATE v2_dispatch_investigation_settings SET lifecycle_enabled=TRUE`)
	// The source's custom port must survive both allocation and monitor cloning.
	f.exec(`UPDATE v2_dispatch_monitor SET check_port=23130 WHERE id=$1`, g.MonitorID)
	f.poolAtPort(443, "192.0.2.210")
	f.poolAtPort(23130, "192.0.2.211", "192.0.2.212", "192.0.2.213")
	pulled := make([]int64, 99)
	for i := range pulled {
		n := int64(i)
		pulled[i] = 1000 + (n/9)*20 + n%9
	}
	g = f.group(g.Host)
	f.outage(g, pulled)
	g = f.group(g.Host)
	// Eleven of the recipients pulled during the last 120 minutes; the rest
	// pulled earlier in the same unchanged entry round.
	first := time.Now().Unix() - 630
	epoch := first - 8000
	f.exec(`UPDATE v2_dispatch_investigation_group SET epoch_at=$2::bigint,ready_at=$2::bigint+1 WHERE id=$1`, g.ID, epoch)
	f.exec(`UPDATE v2_dispatch_investigation_settings SET armed_at=$1`, epoch)
	f.exec(`UPDATE v2_dispatch_investigation_delivery SET delivered_at=$2::bigint-7300 WHERE group_id=$1 AND user_id>=1022`, g.ID, first)
	f.exec(`UPDATE v2_dispatch_investigation_delivery_recent SET delivered_at=$2::bigint-7300 WHERE group_id=$1 AND user_id>=1022`, g.ID, first)
	siblings := f.snapshot("v2_node_address_rule", "v2_insider_rule")
	ctx, cancel := context.WithTimeout(f.ctx, investigationActionBudget)
	defer cancel()
	start := time.Now()
	if err := f.s.processInvestigationAction(ctx, g.ID, 0, false); err != nil {
		t.Fatal("large fragmented group failed within the automatic budget", err)
	}
	var raw []byte
	if err := f.db.QueryRow(`SELECT payload FROM v2_dispatch_investigation_event WHERE group_id=$1 AND kind='filtered'`, g.ID).Scan(&raw); err != nil {
		t.Fatal("no completed split", f.groups(), err)
	}
	var event struct {
		Recent   []int64                  `json:"recent_ids"`
		Older    []int64                  `json:"older_ids"`
		Unpulled []int64                  `json:"unpulled_ids"`
		Parts    []investigationPartition `json:"partitions"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		t.Fatal(err)
	}
	entries, actual, err := usersvc.DispatchEntriesWithInvestigationMembersFrom(f.ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	byHost := map[string]usersvc.DispatchEntry{}
	for _, entry := range entries {
		byHost[entry.Host] = entry
	}
	if len(event.Recent) != 11 || len(event.Older) != 88 || len(event.Unpulled) != 6054 || len(event.Parts) != 3 {
		t.Fatalf("incorrect partition sizes: recent=%d older=%d unpulled=%d parts=%d", len(event.Recent), len(event.Older), len(event.Unpulled), len(event.Parts))
	}
	seen := map[int64]bool{}
	for _, part := range event.Parts {
		if part.Host == "192.0.2.210" || part.Host == g.Host {
			t.Fatal("allocated a mismatched port or retained failed entrance", part.Host)
		}
		child := f.group(part.Host)
		dispatched, err := usersvc.DispatchAccountIDs(f.ctx, f.db, byHost[part.Host])
		if err != nil || !reflect.DeepEqual(dispatched, part.IDs) || len(actual[child.ID].IDs) != len(part.IDs) {
			t.Fatal("actual dispatch differs from the planned partition", child.ID, err)
		}
		for _, id := range []int64{part.IDs[0], part.IDs[len(part.IDs)-1]} {
			servers, err := usersvc.NewDBService(f.s.cfg, f.db).Servers(f.ctx, id, "")
			if err != nil || len(servers) != 1 || fmt.Sprint(servers[0]["host"]) != part.Host || fmt.Sprint(servers[0]["port"]) != "443" {
				t.Fatal("rendered subscription does not use the selected entrance and original service port", id, servers, err)
			}
		}
		var port int64
		if err := f.db.QueryRow(`SELECT check_port FROM v2_dispatch_monitor WHERE id=$1`, child.MonitorID).Scan(&port); err != nil {
			t.Fatal(err)
		}
		if port != 23130 {
			t.Fatal("custom detection port was not inherited", port)
		}
		for _, id := range part.IDs {
			if seen[id] {
				t.Fatal("user assigned to multiple partitions", id)
			}
			seen[id] = true
		}
	}
	if len(seen) != 6153 || !reflect.DeepEqual(siblings, f.snapshot("v2_node_address_rule", "v2_insider_rule")) {
		t.Fatal("lost members or modified original business rules")
	}
	for _, other := range f.groups() {
		if other.Name == "sibling" && (len(other.UserIDs) != 400 || other.Generation != 1) {
			t.Fatal("healthy sibling membership changed", other.ID, strconv.Itoa(len(other.UserIDs)))
		}
	}
	t.Logf("6153 users, fragmented roster, three healthy siblings: automatic allocation and verified split completed in %s", time.Since(start))
}

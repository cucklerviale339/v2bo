package admin

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"forest/go-api/internal/config"
	"forest/go-api/internal/platform/postgres"
	usersvc "forest/go-api/internal/user"
)

// The former upgrade tests created investigation tables while preparing their
// baseline. Remove only those new tables in this unique disposable schema so
// first admin/user/background readers really race on a b23bd18-era database.
func TestPostgresDispatchUpgradeConcurrentFirstReaders(t *testing.T) {
	f := newSplitIntegration(t)
	f.exec(`DROP TABLE v2_dispatch_investigation_member,
v2_dispatch_investigation_delivery_recent,v2_dispatch_investigation_delivery,
v2_dispatch_investigation_event,v2_dispatch_investigation_health,
v2_dispatch_investigation_settings,v2_dispatch_investigation_group`)
	before := f.snapshot("v2_node_address_group", "v2_node_address_rule", "v2_node_address_binding", "v2_insider_rule", "v2_user", "v2_server_vmess", "v2_dns_probe")
	start := make(chan struct{})
	errors := make(chan error, 24)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			var err error
			switch i % 3 {
			case 0:
				err = postgres.EnsureNodeAddressSchema(f.ctx, f.db)
			case 1:
				err = NewDBService(config.Config{}, f.db).ensureNodeAddressSchema(f.ctx)
			case 2:
				_, err = usersvc.NewDBService(config.Config{}, f.db).DispatchEntries(f.ctx)
			}
			if err != nil {
				errors <- fmt.Errorf("first reader %d: %w", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if !reflect.DeepEqual(before, f.snapshot("v2_node_address_group", "v2_node_address_rule", "v2_node_address_binding", "v2_insider_rule", "v2_user", "v2_server_vmess", "v2_dns_probe")) {
		t.Fatal("migration changed existing configuration or accounts")
	}
	var enabled bool
	if err := f.db.QueryRow(`SELECT enabled FROM v2_dispatch_investigation_settings WHERE id=1`).Scan(&enabled); err != nil || enabled {
		t.Fatal("upgrade enabled automation", enabled, err)
	}
}

func TestPostgresDispatchSchemaCanceledFirstAttemptCanRecover(t *testing.T) {
	f := newSplitIntegration(t)
	canceled, cancel := context.WithCancel(f.ctx)
	cancel()
	a := NewDBService(config.Config{}, f.db)
	u := usersvc.NewDBService(config.Config{}, f.db)
	if err := a.ensureNodeAddressSchema(canceled); err == nil {
		t.Fatal("canceled migration unexpectedly succeeded")
	}
	if _, err := u.DispatchEntries(canceled); err == nil {
		t.Fatal("canceled user migration unexpectedly succeeded")
	}
	if err := a.ensureNodeAddressSchema(f.ctx); err != nil {
		t.Fatalf("admin cached a transient schema failure: %v", err)
	}
	if _, err := u.DispatchEntries(f.ctx); err != nil {
		t.Fatalf("user service cached a transient schema failure: %v", err)
	}
}

package httpapi

import (
	"context"
	"strings"
	"testing"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
)

type fakeAutoSplit struct {
	*fakeDNSAdminService
	gets, saves int
	settings    admin.DispatchAutoSplitSettings
	edits       int
}

func (f *fakeAutoSplit) EditDispatchSplitGroups(_ context.Context, req admin.DispatchSplitEditRequest) error {
	f.edits++
	return nil
}

func TestDispatchSplitGroupEditRequiresAdminAndStrictPut(t *testing.T) {
	f := &fakeAutoSplit{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-auto-split/groups"
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{authErr: session.ErrUnauthorized}), WithAdminService(f))
	if r := dnsFailoverRequest(router, "PUT", path, `{"groups":[]}`); r.Code != 403 || f.edits != 0 {
		t.Fatal("anonymous mutation", r.Code)
	}
	deniedUser := &fakeSessionService{user: &session.Identity{ID: 2}, authErr: session.ErrUnauthorized}
	router = NewRouter(config.Config{AdminPath: "control"}, WithSessionService(deniedUser), WithAdminService(f))
	if r := dnsFailoverRequest(router, "PUT", path, `{"groups":[]}`); r.Code != 403 || f.edits != 0 || !deniedUser.lastRequireAdmin {
		t.Fatal("user mutation", r.Code)
	}
	router = NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(f))
	for _, method := range []string{"GET", "POST", "PATCH", "DELETE"} {
		if r := dnsFailoverRequest(router, method, path, `{}`); r.Code != 405 {
			t.Fatal(method, r.Code)
		}
	}
	for _, body := range []string{`{"groups":[],"surprise":true}`, `{"groups":[{"id":1,"surprise":true}]}`} {
		if r := dnsFailoverRequest(router, "PUT", path, body); r.Code != 400 || f.edits != 0 {
			t.Fatal("unknown field accepted", r.Code)
		}
	}
	if r := dnsFailoverRequest(router, "PUT", path, `{"groups":[{"id":2,"revision":1,"parent_group_id":1,"host":"new.example","id_range":"10-20"}]}`); r.Code != 200 || f.edits != 1 || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("edit failed", r.Code)
	}
}

func (f *fakeAutoSplit) GetDispatchAutoSplit(context.Context) (admin.DispatchAutoSplitView, error) {
	f.gets++
	return admin.DispatchAutoSplitView{Settings: f.settings, Operations: []admin.DispatchAutoSplitOperation{}}, nil
}
func (f *fakeAutoSplit) SaveDispatchAutoSplit(_ context.Context, v admin.DispatchAutoSplitSettings) error {
	f.saves++
	f.settings = v
	return nil
}
func TestDispatchAutoSplitRequiresAdminAndExplicitSave(t *testing.T) {
	f := &fakeAutoSplit{fakeDNSAdminService: &fakeDNSAdminService{}}
	path := "/api/v1/control/dns-failover/dispatch-auto-split"
	router := NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{authErr: session.ErrUnauthorized}), WithAdminService(f))
	for _, method := range []string{"GET", "PUT"} {
		if r := dnsFailoverRequest(router, method, path, `{}`); r.Code != 403 {
			t.Fatal(method, r.Code)
		}
	}
	if f.gets != 0 || f.saves != 0 {
		t.Fatal("unauthenticated automation access")
	}
	router = NewRouter(config.Config{AdminPath: "control"}, WithSessionService(&fakeSessionService{user: &session.Identity{ID: 1, IsAdmin: 1}}), WithAdminService(f))
	r := dnsFailoverRequest(router, "GET", path, "")
	if r.Code != 200 || f.saves != 0 || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("GET changed settings", r.Code)
	}
	for _, method := range []string{"POST", "DELETE", "PATCH"} {
		if r := dnsFailoverRequest(router, method, path, `{}`); r.Code != 405 {
			t.Fatal(method, r.Code)
		}
	}
	if r := dnsFailoverRequest(router, "PUT", path, `{"enabled":true,"surprise":1}`); r.Code != 400 || f.saves != 0 {
		t.Fatal("unknown field accepted")
	}
	r = dnsFailoverRequest(router, "PUT", path, `{"enabled":true,"entry_window_minutes":20,"global_window_minutes":60,"global_max":3}`)
	if r.Code != 200 || f.saves != 1 || !f.settings.Enabled || f.settings.EntryWindowMinutes != 20 || f.settings.GlobalMax != 3 {
		t.Fatal("save failed", r.Code, f.settings)
	}
}

package httpapi

import (
	"context"
	"encoding/json"
	"forest/go-api/internal/admin"
	"forest/go-api/internal/aiops"
	"forest/go-api/internal/config"
	"strings"
	"testing"
)

type aiEntryPanelFixture struct {
	admin.Service
	saved  admin.NodeAddressGroupSaveRequest
	inside admin.InsiderRuleSaveRequest
}

func (f *aiEntryPanelFixture) ListNodeAddressGroups(context.Context, *int64) ([]admin.NodeAddressGroupRecord, error) {
	return []admin.NodeAddressGroupRecord{{ID: 1, Name: "group", Rules: []admin.NodeAddressRuleRecord{{ID: 4, Host: "old.example", ExtraNodes: []string{"vless://secret-uuid@private.example:443"}, ExtraNodesPosition: "after"}}}}, nil
}
func (f *aiEntryPanelFixture) SaveNodeAddressGroup(_ context.Context, r admin.NodeAddressGroupSaveRequest) (bool, error) {
	f.saved = r
	return true, nil
}
func (f *aiEntryPanelFixture) ListInsiderRules(context.Context) ([]admin.InsiderRuleRecord, error) {
	return []admin.InsiderRuleRecord{{ID: 3, Name: "inside", Host: "old.example", ExtraNodes: []string{"trojan://secret-password@private.example:443"}, ExtraNodesPosition: "before"}}, nil
}
func (f *aiEntryPanelFixture) SaveInsiderRule(_ context.Context, r admin.InsiderRuleSaveRequest) (bool, error) {
	f.inside = r
	return true, nil
}
func TestAIEntryEditsKeepExcludedSubscriptionLinksServerSide(t *testing.T) {
	f := &aiEntryPanelFixture{}
	p := newPanelOperations(config.Config{}, &routerState{admin: f})
	actor := aiops.PanelOperationActor{ID: 1, IsAdmin: true}
	for _, op := range []string{"entry_addresses.list", "insider_rules.list"} {
		raw, err := p.Execute(context.Background(), actor, op, json.RawMessage(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "secret-") || strings.Contains(string(raw), "vless://") || strings.Contains(string(raw), "trojan://") {
			t.Fatal("subscription credentials leaked", string(raw))
		}
	}
	_, err := p.Execute(context.Background(), actor, "entry_addresses.save", json.RawMessage(`{"id":1,"name":"group","rules":[{"id":4,"host":"new.example","enabled":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.saved.Rules) != 1 || f.saved.Rules[0].Host != "new.example" || len(f.saved.Rules[0].ExtraNodes) != 1 || f.saved.Rules[0].ExtraNodesPosition != "after" {
		t.Fatal("address edit lost excluded data", f.saved)
	}
	_, err = p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":3,"host":"new.example","enabled":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if f.inside.Host != "new.example" || len(f.inside.ExtraNodes) != 1 || f.inside.ExtraNodesPosition != "before" {
		t.Fatal("insider edit lost excluded data", f.inside)
	}
	if err = p.Validate(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":3,"host":"new.example","extra_nodes":[]}`)); err == nil {
		t.Fatal("model allowed to erase excluded credentials")
	}
}

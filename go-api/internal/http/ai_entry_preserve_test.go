package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"forest/go-api/internal/admin"
	"forest/go-api/internal/aiops"
	"forest/go-api/internal/config"
	"reflect"
	"strings"
	"testing"
)

type aiEntryPanelFixture struct {
	admin.Service
	saved       admin.NodeAddressGroupSaveRequest
	inside      admin.InsiderRuleSaveRequest
	insideSaves int
}

func (f *aiEntryPanelFixture) ListNodeAddressGroups(context.Context, *int64) ([]admin.NodeAddressGroupRecord, error) {
	return []admin.NodeAddressGroupRecord{{ID: 1, Name: "group", Rules: []admin.NodeAddressRuleRecord{{ID: 4, Host: "old.example", ExtraNodes: []string{"vless://secret-uuid@private.example:443"}, ExtraNodesPosition: "after"}}}}, nil
}
func (f *aiEntryPanelFixture) SaveNodeAddressGroup(_ context.Context, r admin.NodeAddressGroupSaveRequest) (bool, error) {
	f.saved = r
	return true, nil
}
func (f *aiEntryPanelFixture) ListInsiderRules(context.Context) ([]admin.InsiderRuleRecord, error) {
	return []admin.InsiderRuleRecord{{ID: 3, Name: "inside", Host: "old.example", MatchUserIDs: []string{"10", "20"}, MatchUserIDRanges: []string{"100-200"}, Enabled: 0, ExtraNodes: []string{"trojan://secret-password@private.example:443"}, ExtraNodesPosition: "before"}}, nil
}
func (f *aiEntryPanelFixture) SaveInsiderRule(_ context.Context, r admin.InsiderRuleSaveRequest) (bool, error) {
	f.inside = r
	f.insideSaves++
	return true, nil
}

func TestAIInsiderPartialEditPreservesOrdinaryFields(t *testing.T) {
	f := &aiEntryPanelFixture{}
	p := newPanelOperations(config.Config{}, &routerState{admin: f})
	actor := aiops.PanelOperationActor{ID: 1, IsAdmin: true}
	// The failed production request supplied only id, host and the new ID list.
	_, err := p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":3,"host":"new.example","match_user_ids":["10","20","2615"]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := f.inside
	if f.insideSaves != 1 || r.Name != "inside" || r.Host != "new.example" || r.Enabled == nil || *r.Enabled != 0 || !reflect.DeepEqual(r.MatchUserIDs, []string{"10", "20", "2615"}) || !reflect.DeepEqual(r.MatchUserIDRanges, []string{"100-200"}) || len(r.ExtraNodes) != 1 || r.ExtraNodesPosition != "before" {
		t.Fatalf("partial edit lost stored configuration: %#v", r)
	}
	// Editing just the name must also retain the original host and both selectors.
	_, err = p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":3,"name":"renamed"}`))
	if err != nil || f.inside.Name != "renamed" || f.inside.Host != "old.example" || !reflect.DeepEqual(f.inside.MatchUserIDs, []string{"10", "20"}) {
		t.Fatalf("name-only edit failed: %#v, %v", f.inside, err)
	}
}

func TestAIInsiderValidationRejectsBeforeDispatch(t *testing.T) {
	for _, tc := range []struct{ name, raw, code string }{
		{"new missing name", `{"host":"new.example","match_user_ids":["2615"]}`, "insider_name_required"},
		{"new missing selector", `{"name":"new","host":"new.example"}`, "insider_invalid_arguments"},
		{"new missing host", `{"name":"new","match_user_ids":["2615"]}`, "insider_invalid_arguments"},
		{"explicit empty name", `{"id":3,"name":" "}`, "insider_name_required"},
		{"explicit empty selectors", `{"id":3,"match_user_ids":[],"match_user_id_ranges":[]}`, "insider_invalid_arguments"},
		{"invalid range", `{"id":3,"match_user_id_ranges":["bad"]}`, "insider_invalid_arguments"},
		{"invalid enabled", `{"id":3,"enabled":2}`, "insider_invalid_arguments"},
		{"invalid host", `{"id":3,"host":"https://SECRET.example"}`, "insider_invalid_arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &aiEntryPanelFixture{}
			p := newPanelOperations(config.Config{}, &routerState{admin: f})
			actor := aiops.PanelOperationActor{ID: 1, IsAdmin: true}
			for _, err := range []error{p.Validate(context.Background(), actor, "insider_rules.save", json.RawMessage(tc.raw)), func() error {
				_, err := p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(tc.raw))
				return err
			}()} {
				var validation *aiops.PanelOperationError
				if !errors.As(err, &validation) || !validation.NotExecuted || validation.Code != tc.code || strings.Contains(validation.Error(), "SECRET") {
					t.Fatalf("lost trusted validation diagnosis: %v", err)
				}
			}
			if f.insideSaves != 0 {
				t.Fatal("invalid request reached the write handler")
			}
		})
	}
}

func TestAIInsiderExplicitFieldsAndNewRule(t *testing.T) {
	f := &aiEntryPanelFixture{}
	p := newPanelOperations(config.Config{}, &routerState{admin: f})
	actor := aiops.PanelOperationActor{ID: 1, IsAdmin: true}
	_, err := p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":3,"name":"renamed","enabled":1,"match_user_id_ranges":[]}`))
	if err != nil || f.inside.Name != "renamed" || f.inside.Enabled == nil || *f.inside.Enabled != 1 || len(f.inside.MatchUserIDRanges) != 0 || len(f.inside.MatchUserIDs) != 2 {
		t.Fatalf("explicit replacement ignored: %#v, %v", f.inside, err)
	}
	_, err = p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"name":"new","host":"new.example","match_user_ids":["2615"]}`))
	if err != nil || f.inside.ID != nil || f.inside.Name != "new" || len(f.inside.ExtraNodes) != 0 {
		t.Fatalf("new rule inherited another record: %#v, %v", f.inside, err)
	}
	_, err = p.Execute(context.Background(), actor, "insider_rules.save", json.RawMessage(`{"id":999,"name":"new","host":"new.example","match_user_ids":["2615"]}`))
	if !errors.Is(err, aiops.ErrNotFound) || f.insideSaves != 2 {
		t.Fatalf("missing update target was dispatched: %v", err)
	}
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

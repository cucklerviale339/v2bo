package httpapi

import (
	"context"
	"encoding/json"
	"forest/go-api/internal/aiops"
	"forest/go-api/internal/config"
	"forest/go-api/internal/session"
	"strings"
	"testing"
)

type aiTestSession struct {
	session.Service
	identity *session.Identity
}

func (s aiTestSession) Authenticate(_ context.Context, _ string, admin bool) (*session.Identity, error) {
	if s.identity == nil {
		return nil, session.ErrUnauthorized
	}
	if admin && s.identity.IsAdmin != 1 {
		return nil, session.ErrUnauthorized
	}
	return s.identity, nil
}
func (s aiTestSession) AuthenticateFresh(ctx context.Context, token string, admin bool) (*session.Identity, error) {
	return s.Authenticate(ctx, token, admin)
}
func TestAICatalogUsesCurrentEntryMechanism(t *testing.T) {
	names := map[string]bool{}
	routes := map[string]bool{}
	for _, op := range panelOperationCatalog() {
		if names[op.Name] || routes[op.Method+op.Path] {
			t.Fatal("duplicate", op.Name, op.Path)
		}
		names[op.Name] = true
		routes[op.Method+op.Path] = true
		if !op.AdminOnly {
			t.Fatal("generic delegation must require current administrator guards", op.Name)
		}
		if !panelOperationPathAllowed(op.Path) || strings.Contains(op.Path, "/client-entry-user-policy") || strings.Contains(op.Path, "entry-monitors") || op.Method == "POST" && op.Path == "/dns-failover/dispatch-runs" {
			t.Fatal("incompatible operation", op)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Required   []string                   `json:"required"`
			Additional bool                       `json:"additionalProperties"`
		}
		if json.Unmarshal(op.Parameters, &schema) != nil || schema.Properties == nil || schema.Additional {
			t.Fatal("invalid schema", op.Name)
		}
		for _, key := range schema.Required {
			if _, ok := schema.Properties[key]; !ok {
				t.Fatal("undeclared field", op.Name, key)
			}
		}
		if op.Name == "entry_addresses.save" || op.Name == "insider_rules.save" {
			if _, ok := schema.Properties["host"]; !ok && op.Name == "insider_rules.save" {
				t.Fatal("missing lower-case host")
			}
			if _, ok := schema.Properties["ID"]; ok {
				t.Fatal("Go DTO fields leaked into API schema")
			}
		}
	}
	for _, name := range []string{"entry_addresses.list", "entry_addresses.save", "insider_rules.list", "insider_rules.save", "entry_monitors.list", "entry_monitors.save", "ip_pool.save", "ip_pool.delete_faulty", "entry_checks.history", "nodes.vmess.save", "dns.records", "config.read", "config.save"} {
		if !names[name] {
			t.Fatal("missing capability", name)
		}
	}
	p := newPanelOperations(config.Config{}, &routerState{})
	if err := p.Validate(context.Background(), aiops.PanelOperationActor{ID: 2}, "nodes.list", json.RawMessage(`{}`)); err != aiops.ErrForbidden {
		t.Fatal("staff delegated admin identity", err)
	}
	if err := p.Validate(context.Background(), aiops.PanelOperationActor{ID: 1, IsAdmin: true}, "config.save", json.RawMessage(`{"payment":{"key":"x"}}`)); err == nil {
		t.Fatal("payment config escaped boundary")
	}
}

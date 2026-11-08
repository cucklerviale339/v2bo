package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/aiops"
)

// Extra subscription links contain credentials and are outside this adaptation.
// Keep them on the server while the model edits ordinary address fields.
func (p *panelOperations) preserveAIEntryLinks(ctx context.Context, path string, params map[string]any) error {
	if path != "/server/address/save" && path != "/server/insider/save" {
		return nil
	}
	if p.state.admin == nil {
		return aiops.ErrUnavailable
	}
	id, existing := panelPositiveID(params["id"])
	if !existing {
		return nil
	}
	if path == "/server/insider/save" {
		rows, err := p.state.admin.ListInsiderRules(ctx)
		if err != nil {
			return aiops.ErrUnavailable
		}
		for _, row := range rows {
			if row.ID == id {
				// The business endpoint replaces a full record. AI edits are patches:
				// absence keeps the stored value; explicit empty values still validate.
				for key, value := range map[string]any{
					"name": row.Name, "host": row.Host, "enabled": row.Enabled,
					"match_user_ids": row.MatchUserIDs, "match_user_id_ranges": row.MatchUserIDRanges,
					"members": row.Members,
				} {
					if _, supplied := params[key]; !supplied {
						params[key] = value
					}
				}
				params["extra_nodes"] = row.ExtraNodes
				params["extra_nodes_position"] = row.ExtraNodesPosition
				return nil
			}
		}
		return aiops.ErrNotFound
	}
	groups, err := p.state.admin.ListNodeAddressGroups(ctx, &id)
	if err != nil {
		return aiops.ErrUnavailable
	}
	if len(groups) != 1 {
		return aiops.ErrNotFound
	}
	rules, _ := params["rules"].([]any)
	for _, value := range rules {
		rule, ok := value.(map[string]any)
		if !ok {
			return aiops.ErrValidation
		}
		ruleID, ok := panelPositiveID(rule["id"])
		if !ok {
			continue
		}
		found := false
		for _, old := range groups[0].Rules {
			if old.ID == ruleID {
				rule["extra_nodes"] = old.ExtraNodes
				rule["extra_nodes_position"] = old.ExtraNodesPosition
				found = true
				break
			}
		}
		if !found {
			return aiops.ErrNotFound
		}
	}
	return nil
}

func validateAIInsiderSave(path string, params map[string]any) error {
	if path != "/server/insider/save" {
		return nil
	}
	invalid := func(code string) error {
		return &aiops.PanelOperationError{Status: http.StatusBadRequest, Code: code, NotExecuted: true}
	}
	raw, err := json.Marshal(params)
	var payload insiderRulePayload
	if err != nil || json.Unmarshal(raw, &payload) != nil {
		return invalid("insider_invalid_arguments")
	}
	req, err := payload.saveRequest()
	if err != nil {
		return invalid("insider_invalid_arguments")
	}
	if err := admin.ValidateInsiderRuleSaveRequest(req); err != nil {
		if strings.TrimSpace(req.Name) == "" {
			return invalid("insider_name_required")
		}
		return invalid("insider_invalid_arguments")
	}
	return nil
}

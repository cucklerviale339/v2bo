package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/session"
)

func handleUserMailPreview(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service, staff bool) bool {
	if staff {
		if _, ok := authenticateStaffRequest(w, r, sessionService); !ok {
			return true
		}
	} else if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "method not allowed"})
		return true
	}
	previewer, ok := adminService.(admin.UserMailPreviewer)
	if !ok {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "mail preview unavailable"})
		return true
	}
	inputs, err := readUserMailInputs(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return true
	}
	filters := userFilters(inputs)
	if staff {
		filters = enforceStaffUserScope(filters)
	}
	preview, err := previewer.PreviewUserMail(r.Context(), admin.UserMailRequest{
		Sort: strings.TrimSpace(inputs["sort"]), SortType: strings.TrimSpace(inputs["sort_type"]), Filters: filters,
	})
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": preview})
	return true
}

func readUserMailInputs(r *http.Request) (map[string]string, error) {
	inputs, err := readInputs(r)
	if err != nil {
		return nil, err
	}
	invalidFilter := errors.New("群发筛选条件格式错误，已停止处理")
	if _, exists := inputs["filter"]; exists {
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			return nil, invalidFilter
		}
		var payload struct {
			Filter []struct {
				Key       string
				Condition string
				Value     json.RawMessage
			}
		}
		if err := readJSONBody(r, &payload); err != nil {
			return nil, invalidFilter
		}
		for key := range inputs {
			if strings.HasPrefix(key, "filter[") {
				return nil, invalidFilter
			}
		}
		for index, entry := range payload.Filter {
			if len(entry.Value) == 0 || string(entry.Value) == "null" {
				return nil, invalidFilter
			}
			var value string
			if err := json.Unmarshal(entry.Value, &value); err != nil {
				var number json.Number
				if err := json.Unmarshal(entry.Value, &number); err != nil || number == "" {
					return nil, invalidFilter
				}
				value = number.String()
			}
			inputs[fmt.Sprintf("filter[%d][key]", index)] = entry.Key
			inputs[fmt.Sprintf("filter[%d][condition]", index)] = entry.Condition
			inputs[fmt.Sprintf("filter[%d][value]", index)] = value
		}
	}
	for key := range inputs {
		if strings.HasPrefix(key, "filter[") {
			if _, field, ok := nestedIndexedFieldKey(key, "filter"); !ok || (field != "key" && field != "condition" && field != "value") {
				return nil, invalidFilter
			}
		}
	}
	for _, filter := range indexedNestedFieldMap(inputs, "filter") {
		_, hasValue := filter["value"]
		if strings.TrimSpace(filter["key"]) == "" || strings.TrimSpace(filter["condition"]) == "" || !hasValue {
			return nil, invalidFilter
		}
	}
	return inputs, nil
}

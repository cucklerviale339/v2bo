package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/session"
)

type nodeAddressGroupPayload struct {
	ID          *json.Number             `json:"id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Enabled     *json.Number             `json:"enabled"`
	Rules       []nodeAddressRulePayload `json:"rules"`
}

type nodeAddressRulePayload struct {
	ID                *json.Number `json:"id"`
	Name              string       `json:"name"`
	Host              string       `json:"host"`
	MatchUserIDs      []string     `json:"match_user_ids"`
	MatchUserIDRanges []string     `json:"match_user_id_ranges"`
	Enabled           *json.Number `json:"enabled"`
	Sort              *json.Number `json:"sort"`
}

func handleAdminNodeAddressGroupFetch(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return true
	}
	var id *int64
	if raw := strings.TrimSpace(inputs["id"]); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": "地址组不存在"})
			return true
		}
		id = &value
	}

	data, err := adminService.ListNodeAddressGroups(r.Context(), id)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
	return true
}

func handleAdminNodeAddressGroupSave(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	var payload nodeAddressGroupPayload
	if err := readJSONBody(r, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return true
	}
	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return true
	}
	if payload.ID == nil {
		payload.ID = jsonNumberFromInput(inputs, "id")
	}
	if strings.TrimSpace(payload.Name) == "" {
		payload.Name = strings.TrimSpace(inputs["name"])
	}
	if strings.TrimSpace(payload.Description) == "" {
		payload.Description = strings.TrimSpace(inputs["description"])
	}
	if payload.Enabled == nil {
		payload.Enabled = jsonNumberFromInput(inputs, "enabled")
	}

	req, ok := buildNodeAddressGroupSaveRequest(w, payload)
	if !ok {
		return true
	}
	saved, err := adminService.SaveNodeAddressGroup(r.Context(), req)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": saved})
	return true
}

func handleAdminNodeAddressGroupDrop(w http.ResponseWriter, r *http.Request, sessionService session.Service, adminService admin.Service) bool {
	if _, ok := authenticateRequest(w, r, sessionService, true); !ok {
		return true
	}
	if adminService == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}

	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
		return true
	}
	id, err := strconv.ParseInt(strings.TrimSpace(inputs["id"]), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "地址组不存在"})
		return true
	}

	deleted, err := adminService.DeleteNodeAddressGroup(r.Context(), id)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": deleted})
	return true
}

func buildNodeAddressGroupSaveRequest(w http.ResponseWriter, payload nodeAddressGroupPayload) (admin.NodeAddressGroupSaveRequest, bool) {
	id, err := jsonNumberToInt64Pointer(payload.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "地址组格式不正确"})
		return admin.NodeAddressGroupSaveRequest{}, false
	}
	enabled, err := jsonNumberToInt64Pointer(payload.Enabled)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "启用状态格式不正确"})
		return admin.NodeAddressGroupSaveRequest{}, false
	}

	req := admin.NodeAddressGroupSaveRequest{
		ID:          id,
		Name:        payload.Name,
		Description: payload.Description,
		Enabled:     enabled,
		Rules:       make([]admin.NodeAddressRuleSaveRequest, 0, len(payload.Rules)),
	}
	for _, item := range payload.Rules {
		rule, ok := buildNodeAddressRuleSaveRequest(w, item)
		if !ok {
			return admin.NodeAddressGroupSaveRequest{}, false
		}
		req.Rules = append(req.Rules, rule)
	}
	return req, true
}

func buildNodeAddressRuleSaveRequest(w http.ResponseWriter, item nodeAddressRulePayload) (admin.NodeAddressRuleSaveRequest, bool) {
	id, err := jsonNumberToInt64Pointer(item.ID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "规则格式不正确"})
		return admin.NodeAddressRuleSaveRequest{}, false
	}
	enabled, err := jsonNumberToInt64Pointer(item.Enabled)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "规则启用状态格式不正确"})
		return admin.NodeAddressRuleSaveRequest{}, false
	}
	sortValue, err := jsonNumberToInt64Pointer(item.Sort)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "排序格式不正确"})
		return admin.NodeAddressRuleSaveRequest{}, false
	}

	return admin.NodeAddressRuleSaveRequest{
		ID:                id,
		Name:              item.Name,
		Host:              item.Host,
		MatchUserIDs:      item.MatchUserIDs,
		MatchUserIDRanges: item.MatchUserIDRanges,
		Enabled:           enabled,
		Sort:              sortValue,
	}, true
}

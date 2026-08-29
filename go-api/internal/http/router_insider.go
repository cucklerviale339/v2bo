package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"forest/go-api/internal/admin"
	"forest/go-api/internal/session"
)

type insiderRulePayload struct {
	ID                 *json.Number              `json:"id"`
	Name               string                    `json:"name"`
	MatchUserIDs       []string                  `json:"match_user_ids"`
	MatchUserIDRanges  []string                  `json:"match_user_id_ranges"`
	Members            []admin.InsiderRuleMember `json:"members"`
	Host               string                    `json:"host"`
	ExtraNodes         []string                  `json:"extra_nodes"`
	ExtraNodesPosition string                    `json:"extra_nodes_position"`
	Enabled, Sort      *json.Number
}

func handleAdminInsiderRuleFetch(w http.ResponseWriter, r *http.Request, sessions session.Service, service admin.Service) bool {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessions, true); !ok {
		return true
	}
	if service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	data, err := service.ListInsiderRules(r.Context())
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
	return true
}

func handleAdminInsiderRuleSave(w http.ResponseWriter, r *http.Request, sessions session.Service, service admin.Service) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessions, true); !ok {
		return true
	}
	if service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var payload insiderRulePayload
	if err := readJSONBody(r, &payload); err != nil {
		writeJSON(w, 400, map[string]any{"message": err.Error()})
		return true
	}
	id, err := jsonNumberToInt64Pointer(payload.ID)
	if err != nil {
		writeJSON(w, 400, map[string]any{"message": "规则格式错误"})
		return true
	}
	enabled, err := jsonNumberToInt64Pointer(payload.Enabled)
	if err != nil {
		writeJSON(w, 400, map[string]any{"message": "状态格式错误"})
		return true
	}
	sortValue, err := jsonNumberToInt64Pointer(payload.Sort)
	if err != nil {
		writeJSON(w, 400, map[string]any{"message": "排序格式错误"})
		return true
	}
	ok, err := service.SaveInsiderRule(r.Context(), admin.InsiderRuleSaveRequest{ID: id, Name: payload.Name, MatchUserIDs: payload.MatchUserIDs, MatchUserIDRanges: payload.MatchUserIDRanges, Members: payload.Members, Host: payload.Host, ExtraNodes: payload.ExtraNodes, ExtraNodesPosition: payload.ExtraNodesPosition, Enabled: enabled, Sort: sortValue})
	if err != nil {
		if errors.Is(err, admin.ErrInvalidInsiderRule) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": strings.TrimPrefix(err.Error(), admin.ErrInvalidInsiderRule.Error()+": ")})
			return true
		}
		return handleAdminError(w, err)
	}
	writeJSON(w, 200, map[string]any{"data": ok})
	return true
}

func handleAdminInsiderRuleDrop(w http.ResponseWriter, r *http.Request, sessions session.Service, service admin.Service) bool {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"message": "请求方式不支持"})
		return true
	}
	if _, ok := authenticateRequest(w, r, sessions, true); !ok {
		return true
	}
	if service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"message": "admin service unavailable"})
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	inputs, err := readInputs(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"message": err.Error()})
		return true
	}
	id, err := strconv.ParseInt(strings.TrimSpace(inputs["id"]), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, 400, map[string]any{"message": "内鬼规则不存在"})
		return true
	}
	ok, err := service.DeleteInsiderRule(r.Context(), id)
	if err != nil {
		return handleAdminError(w, err)
	}
	writeJSON(w, 200, map[string]any{"data": ok})
	return true
}

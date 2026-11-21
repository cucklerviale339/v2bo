package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
)

// The audit payload may contain UI snapshots in any shape. The risk replay
// reads a closed set of domain transitions and only the fields each consumes.
const dispatchRiskFields = "before host"

func dispatchRiskTransitionFields(kind string) string {
	switch kind {
	case "filtered", "bisected", "whitelist_bisected", "no_pulls", "branch_fault":
		return " pulled_ids unpulled_ids partitions evidence risk_narrowing confirmation"
	case "stable_promoted", "whitelist_promoted", "members_moved", "stage_corrected", "members_admitted", "started":
		return " user_ids target_group_id source_group_ids merged_group_ids promotion_hold"
	case "recovered", "observation_repaired", "whitelist_failed_over":
		return " partitions"
	default:
		return ""
	}
}

func decodeDispatchRiskPayload(kind string, raw json.RawMessage) (dispatchRiskPayload, error) {
	var payload dispatchRiskPayload
	fields := dispatchRiskTransitionFields(kind)
	if fields == "" {
		// These actions can update the historical host index, but cannot
		// alter membership, clear evidence or block the worker.
		switch kind {
		case "edited", "confirmed_entry", "manual_trigger", "observation_imported", "global_released":
			var hints struct {
				Host   json.RawMessage `json:"host"`
				Before json.RawMessage `json:"before"`
			}
			if json.Unmarshal(raw, &hints) == nil {
				payload.Before = hints.Before
				var host string
				if json.Unmarshal(hints.Host, &host) == nil {
					payload.Host = host
				}
			}
		}
		return payload, nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return payload, err
	}
	if envelope == nil {
		return payload, errors.New("expected a risk transition object")
	}
	if rawVersion, ok := envelope["risk_schema_version"]; ok {
		var version int
		if err := json.Unmarshal(rawVersion, &version); err != nil || version != 1 {
			return payload, errors.New("unsupported risk event schema version")
		}
	}
	selected := make(map[string]json.RawMessage)
	for _, field := range bytes.Fields([]byte(dispatchRiskFields + fields)) {
		key := string(field)
		if value, found := envelope[key]; found {
			selected[key] = value
		}
	}
	canonical, err := json.Marshal(selected)
	if err != nil {
		return payload, err
	}
	err = json.Unmarshal(canonical, &payload)
	return payload, err
}

func dispatchAuditHost(raw json.RawMessage) string {
	var snapshot struct {
		Host string `json:"host"`
	}
	// A legacy array is a roster snapshot. It provides no host hint.
	if json.Unmarshal(raw, &snapshot) == nil {
		return snapshot.Host
	}
	return ""
}

func EncodeDispatchRiskTransition(kind string, raw json.RawMessage) (string, error) {
	if dispatchRiskTransitionFields(kind) == "" {
		return "", nil
	}
	payload, err := decodeDispatchRiskPayload(kind, raw)
	if err != nil {
		return "", err
	}
	host := dispatchAuditHost(payload.Before)
	payload.Before = nil
	if host != "" {
		payload.Before, err = json.Marshal(map[string]string{"host": host})
		if err != nil {
			return "", err
		}
	}
	result, err := json.Marshal(struct {
		Version int `json:"risk_schema_version"`
		dispatchRiskPayload
	}{Version: 1, dispatchRiskPayload: payload})
	return string(result), err
}

type DispatchRiskHistoryIssue struct {
	EventID int64  `json:"event_id"`
	RootID  int64  `json:"root_id"`
	GroupID int64  `json:"group_id"`
	Kind    string `json:"kind"`
	cause   error
}

func (e *DispatchRiskHistoryIssue) Error() string {
	return fmt.Sprintf("risk event %d (%s): %v", e.EventID, e.Kind, e.cause)
}

func (e *DispatchRiskHistoryIssue) Unwrap() error { return e.cause }

func saveDispatchRiskHistoryIssue(ctx context.Context, tx *sql.Tx, issue *DispatchRiskHistoryIssue) error {
	if issue == nil {
		_, err := tx.ExecContext(ctx, `DELETE FROM v2_dispatch_risk_history_issue WHERE id=1`)
		return err
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO v2_dispatch_risk_history_issue(id,event_id,root_id,group_id,kind)
VALUES(1,$1,$2,$3,$4) ON CONFLICT(id) DO UPDATE SET event_id=EXCLUDED.event_id,
root_id=EXCLUDED.root_id,group_id=EXCLUDED.group_id,kind=EXCLUDED.kind
WHERE v2_dispatch_risk_history_issue.event_id IS DISTINCT FROM EXCLUDED.event_id`,
		issue.EventID, issue.RootID, issue.GroupID, issue.Kind)
	return err
}

func ReadDispatchRiskHistoryIssue(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (*DispatchRiskHistoryIssue, error) {
	var issue DispatchRiskHistoryIssue
	err := db.QueryRowContext(ctx, `SELECT event_id,root_id,group_id,kind FROM v2_dispatch_risk_history_issue WHERE id=1`).
		Scan(&issue.EventID, &issue.RootID, &issue.GroupID, &issue.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &issue, nil
}

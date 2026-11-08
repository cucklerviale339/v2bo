package aiops

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"forest/go-api/internal/config"
	"github.com/DATA-DOG/go-sqlmock"
)

type validatingPanelRuntime struct {
	fixturePanelOperations
	failValidationAt int
	validationError  error
}

func (p *validatingPanelRuntime) Validate(ctx context.Context, actor PanelOperationActor, name string, raw json.RawMessage) error {
	if err := p.fixturePanelOperations.Validate(ctx, actor, name, raw); err != nil {
		return err
	}
	if p.validations == p.failValidationAt {
		return p.validationError
	}
	return nil
}

// Exercise the actual action executor, including all pre-dispatch validation
// passes. HTTP 400 after dispatch must remain unknown without a trusted marker.
func TestAIInsiderActionValidationPreservesExecutionState(t *testing.T) {
	for _, tc := range []struct {
		name             string
		failValidationAt int
		err              *PanelOperationError
		wantStatus       string
		wantExecutions   int
	}{
		{"origin validation", 1, &PanelOperationError{Status: 400, Code: "insider_name_required", NotExecuted: true}, "failed", 0},
		{"approver validation", 2, &PanelOperationError{Status: 400, Code: "insider_invalid_arguments", NotExecuted: true}, "failed", 0},
		{"effective actor validation", 3, &PanelOperationError{Status: 400, Code: "insider_name_required", NotExecuted: true}, "failed", 0},
		{"adapter preflight", 0, &PanelOperationError{Status: 400, Code: "insider_invalid_arguments", NotExecuted: true}, "failed", 1},
		{"untrusted HTTP error", 0, &PanelOperationError{Status: 400, Code: "insider_name_required", Message: "RAW_SECRET"}, "unknown", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			s := NewService(config.Config{}, db, nil)
			defer s.Close()
			op := fixtureOperation("insider_rules.save", "/server/insider/save", true, true)
			runtime := &validatingPanelRuntime{fixturePanelOperations: fixturePanelOperations{ops: []PanelOperation{op}}, failValidationAt: tc.failValidationAt, validationError: tc.err}
			if tc.failValidationAt == 0 {
				runtime.onExecute = func(context.Context) error { return tc.err }
			}
			s.SetPanelOperations(runtime)
			actor := func() {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT is_admin=1 FROM v2_user WHERE id=$1 AND banned=0 AND (is_admin=1 OR is_staff=1)`)).WithArgs(int64(1)).WillReturnRows(sqlmock.NewRows([]string{"admin"}).AddRow(true))
			}
			adminSession := func() {
				mock.ExpectQuery(regexp.QuoteMeta(`SELECT u.id FROM v2_ai_session s JOIN v2_user u ON u.id=s.created_by WHERE s.id=$1 AND u.is_admin=1 AND u.banned=0`)).WithArgs(int64(7)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))
			}
			actor()
			actor()
			adminSession()
			for i := 0; i < 2; i++ {
				mock.ExpectQuery(regexp.QuoteMeta(sessionAccessSQL)).WithArgs(int64(7), int64(1)).WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(7))
			}
			if tc.failValidationAt == 0 || tc.failValidationAt == 3 {
				actor()
				actor()
				adminSession()
			}
			if tc.failValidationAt == 0 {
				mock.ExpectQuery(`SELECT EXISTS\(SELECT 1 FROM v2_ai_action`).WithArgs(int64(51)).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
			}
			params := json.RawMessage(`{"id":11,"match_user_ids":["42"]}`)
			payload, _ := json.Marshal(panelOperationPayload{Operation: op.Name, Parameters: params})
			a := Action{ID: 51, Kind: "panel_operation", ActorID: 1, ApprovedBy: 1, SessionID: 7, Payload: payload}
			status, output, message := s.executePanelOperation(context.Background(), a, panelOperationSnapshot(op, params))
			if status != tc.wantStatus || runtime.count() != tc.wantExecutions || strings.Contains(output+message, "RAW_SECRET") {
				t.Fatalf("status=%s executions=%d output=%s message=%s", status, runtime.count(), output, message)
			}
			if tc.wantStatus == "failed" && (panelActionRecovery(Action{Kind: "panel_operation", Status: status, Output: output}) != panelRecoveryPreflight || !strings.Contains(message, "未执行保存")) {
				t.Fatalf("validation lost recovery state: %s / %s", output, message)
			}
			if tc.wantStatus == "unknown" && output != "" {
				t.Fatal("untrusted response granted a not-executed marker")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

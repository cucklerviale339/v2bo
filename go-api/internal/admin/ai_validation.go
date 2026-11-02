package admin

import "encoding/json"

type ManagedServerValidationError struct{ message string }

func (e *ManagedServerValidationError) Error() string { return e.message }
func ValidateManagedServerSavePayload(kind string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return &ManagedServerValidationError{message: "节点参数无效"}
	}
	var cloned map[string]any
	if json.Unmarshal(raw, &cloned) != nil {
		return &ManagedServerValidationError{message: "节点参数无效"}
	}
	_, _, err = normalizeManagedServerSavePayload(kind, cloned)
	if err != nil {
		return &ManagedServerValidationError{message: err.Error()}
	}
	return nil
}

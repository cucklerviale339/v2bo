package aiops

import (
	"encoding/json"
	"strconv"
)

// These DTOs are intentionally separate from admin DTOs. Adding a password,
// token or config field to an admin response must not expand AI model exposure.
type pageDTO[T any] struct {
	Items       []T   `json:"items"`
	Total       int64 `json:"total"`
	Limit       int   `json:"limit"`
	Offset      int   `json:"offset"`
	NextOffset  *int  `json:"next_offset,omitempty"`
	Truncated   bool  `json:"truncated"`
	SizeLimited bool  `json:"size_limited,omitempty"`
}

// Keep every tool result below the chat persistence/context guard. Items are
// projected and individually bounded before this page budget is applied.
const maxToolOutputBytes = 30000
const maxToolItemBytes = 16000

func makePage[T any](items []T, total int64, limit, offset int) pageDTO[T] {
	p := pageDTO[T]{Items: items, Total: total, Limit: limit, Offset: offset}
	next := offset + len(items)
	p.Truncated = int64(next) < total
	if p.Truncated && len(items) > 0 {
		p.NextOffset = &next
	}
	return p
}

func boundedPage[T any](items []T, total int64, limit, offset, budget int) pageDTO[T] {
	if items == nil {
		items = []T{}
	}
	build := func(count int) pageDTO[T] {
		p := makePage(items[:count], total, limit, offset)
		p.SizeLimited = count < len(items)
		return p
	}
	full := build(len(items))
	if jsonSize(full) <= budget || len(items) <= 1 {
		return full
	}
	// Find the largest fitting prefix without O(n²) JSON work for long pages.
	// A single item is pre-bounded below maxToolItemBytes by its projection.
	low, high := 1, len(items)-1
	for low < high {
		middle := (low + high + 1) / 2
		if jsonSize(build(middle)) <= budget {
			low = middle
		} else {
			high = middle - 1
		}
	}
	return build(low)
}

func jsonSize(value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return maxToolOutputBytes + 1
	}
	return len(raw)
}
func window[T any](items []T, limit, offset int) []T {
	if offset >= len(items) {
		return []T{}
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	return items[offset:end]
}
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
func text(m map[string]any, key string, n int) string { v, _ := m[key].(string); return clip(v, n) }
func integer(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}
func optionalInt(m map[string]any, key string) *int64 {
	if v, ok := m[key]; !ok || v == nil {
		return nil
	}
	v := integer(m, key)
	return &v
}
func scalarList(v any) []string {
	out := []string{}
	switch list := v.(type) {
	case []string:
		for _, s := range window(list, 50, 0) {
			out = append(out, clip(s, 128))
		}
	case []any:
		for _, x := range window(list, 50, 0) {
			switch s := x.(type) {
			case string:
				out = append(out, clip(s, 128))
			case float64:
				out = append(out, strconv.FormatInt(int64(s), 10))
			case int64:
				out = append(out, strconv.FormatInt(s, 10))
			}
		}
	}
	return out
}

type panelDTO struct {
	Schedule            bool   `json:"schedule"`
	Horizon             bool   `json:"horizon"`
	ScheduleLastRuntime *int64 `json:"schedule_last_runtime"`
	QueueRunning        bool   `json:"queue_running"`
	FailedJobs          int64  `json:"failed_jobs"`
	RecentJobs          int64  `json:"recent_jobs"`
	JobsPerMinute       int64  `json:"jobs_per_minute"`
	Workers             int64  `json:"workers"`
	PausedMasters       int64  `json:"paused_masters"`
}
type userDTO struct {
	ID             int64  `json:"id"`
	Email          string `json:"email"`
	PlanID         *int64 `json:"plan_id"`
	PlanName       string `json:"plan_name"`
	GroupID        *int64 `json:"group_id"`
	Banned         bool   `json:"banned"`
	TransferEnable int64  `json:"transfer_enable_bytes"`
	Upload         int64  `json:"upload_bytes"`
	Download       int64  `json:"download_bytes"`
	ExpiredAt      *int64 `json:"expired_at"`
	DeviceLimit    *int64 `json:"device_limit"`
	SpeedLimit     *int64 `json:"speed_limit"`
	LastSeenAt     int64  `json:"last_seen_at"`
	CreatedAt      int64  `json:"created_at"`
}
type lookupDTO struct {
	Found bool     `json:"found"`
	User  *userDTO `json:"user,omitempty"`
}

func projectUser(m map[string]any) userDTO {
	return userDTO{ID: integer(m, "id"), Email: text(m, "email", 254), PlanID: optionalInt(m, "plan_id"), PlanName: text(m, "plan_name", 128), GroupID: optionalInt(m, "group_id"), Banned: integer(m, "banned") != 0, TransferEnable: integer(m, "transfer_enable"), Upload: integer(m, "u"), Download: integer(m, "d"), ExpiredAt: optionalInt(m, "expired_at"), DeviceLimit: optionalInt(m, "device_limit"), SpeedLimit: optionalInt(m, "speed_limit"), LastSeenAt: integer(m, "t"), CreatedAt: integer(m, "created_at")}
}

type orderDTO struct {
	ID          int64  `json:"id"`
	TradeNo     string `json:"trade_no"`
	UserID      int64  `json:"user_id"`
	PlanID      int64  `json:"plan_id"`
	PlanName    string `json:"plan_name"`
	Period      string `json:"period"`
	TotalAmount int64  `json:"total_amount_cents"`
	Status      int64  `json:"status"`
	CreatedAt   int64  `json:"created_at"`
	PaidAt      *int64 `json:"paid_at"`
}

func projectOrder(m map[string]any) orderDTO {
	return orderDTO{ID: integer(m, "id"), TradeNo: text(m, "trade_no", 128), UserID: integer(m, "user_id"), PlanID: integer(m, "plan_id"), PlanName: text(m, "plan_name", 128), Period: text(m, "period", 64), TotalAmount: integer(m, "total_amount"), Status: integer(m, "status"), CreatedAt: integer(m, "created_at"), PaidAt: optionalInt(m, "paid_at")}
}

type nodeDTO struct {
	ID                int64    `json:"id"`
	Type              string   `json:"type"`
	Name              string   `json:"name"`
	Host              string   `json:"host"`
	Port              string   `json:"port"`
	ServerPort        int64    `json:"server_port"`
	Visible           bool     `json:"visible"`
	GroupIDs          []string `json:"group_ids"`
	GroupIDsTruncated bool     `json:"group_ids_truncated"`
	Online            int64    `json:"online"`
	LastCheckAt       int64    `json:"last_check_at"`
	LastPushAt        int64    `json:"last_push_at"`
	AvailableStatus   int64    `json:"available_status"`
}

func projectNode(m map[string]any) nodeDTO {
	port := text(m, "port", 32)
	if port == "" {
		port = strconv.FormatInt(integer(m, "port"), 10)
	}
	out := nodeDTO{ID: integer(m, "id"), Type: text(m, "type", 20), Name: text(m, "name", 128), Host: text(m, "host", 255), Port: port, ServerPort: integer(m, "server_port"), Visible: integer(m, "show") != 0, GroupIDs: scalarList(m["group_id"]), Online: integer(m, "online"), LastCheckAt: integer(m, "last_check_at"), LastPushAt: integer(m, "last_push_at"), AvailableStatus: integer(m, "available_status")}
	switch ids := m["group_id"].(type) {
	case []string:
		out.GroupIDsTruncated = len(ids) > len(out.GroupIDs)
	case []any:
		out.GroupIDsTruncated = len(ids) > len(out.GroupIDs)
	}
	for jsonSize(out) > maxToolItemBytes && len(out.GroupIDs) > 0 {
		out.GroupIDs = out.GroupIDs[:len(out.GroupIDs)/2]
		out.GroupIDsTruncated = true
	}
	return out
}

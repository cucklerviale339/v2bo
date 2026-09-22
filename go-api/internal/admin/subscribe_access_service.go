package admin

import "context"

type SubscribeAccessStatsRequest struct {
	Keyword  string
	Current  int64
	PageSize int64
	Sort     string
}

type SubscribeAccessService interface {
	GetSubscribeAccessStats(ctx context.Context, req SubscribeAccessStatsRequest) (map[string]any, error)
	GetSubscribeAccessUserDetail(ctx context.Context, userID int64) (map[string]any, error)
	SearchSubscribeAccessByUA(ctx context.Context, keyword string, current, pageSize int64) (map[string]any, error)
	SetSubscribeAccessRetention(ctx context.Context, days int64) (bool, error)
	GetDailyLowTrafficUsers(ctx context.Context, current, pageSize, thresholdBytes int64) (map[string]any, error)
	GetConsecutiveLowTrafficUsers(ctx context.Context, current, pageSize, thresholdBytes, days int64) (map[string]any, error)
}

var _ SubscribeAccessService = (*DBService)(nil)

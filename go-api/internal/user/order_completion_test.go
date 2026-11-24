package user

import (
	"context"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"forest/go-api/internal/config"
)

func TestOpenOrderAppliesConfiguredCompletionTrafficReset(t *testing.T) {
	for _, tc := range []struct {
		name          string
		orderType     int64
		cfg           config.Config
		wantReset     bool
		wantNewAnchor bool
	}{
		{name: "early renewal retains usage", orderType: 2},
		{name: "renewal resets and keeps its order day", orderType: 2, cfg: config.Config{RenewOrderEventID: 1}, wantReset: true},
		{name: "new purchase action does not affect renewal", orderType: 2, cfg: config.Config{NewOrderEventID: 1}},
		{name: "plan change does not reset by default", orderType: 3, wantNewAnchor: true},
		{name: "plan change resets with new order day", orderType: 3, cfg: config.Config{ChangeOrderEventID: 1}, wantReset: true, wantNewAnchor: true},
		{name: "new purchase retains standard reset with action off", orderType: 1, wantReset: true, wantNewAnchor: true},
		{name: "new purchase with action on", orderType: 1, cfg: config.Config{NewOrderEventID: 1}, wantReset: true, wantNewAnchor: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			ctx := context.Background()
			const userID int64 = 7
			const planID int64 = 12
			const groupID int64 = 4
			const orderID int64 = 18
			const transferGB int64 = 100

			// Include nonzero counters and an expiry on a different day to isolate the configured renewal reset.
			expiry := time.Now().AddDate(0, 0, 10).Unix()
			mock.ExpectBegin()
			mock.ExpectQuery(`(?s)SELECT.*FROM v2_user WHERE id = \$1 FOR UPDATE`).WithArgs(userID).
				WillReturnRows(sqlmock.NewRows([]string{"id", "invite_user_id", "balance", "commission_balance", "discount", "commission_type", "commission_rate", "u", "d", "transfer_enable", "device_limit", "banned", "group_id", "plan_id", "speed_limit", "expired_at"}).
					AddRow(userID, nil, 0, 0, nil, 0, nil, 230, 120, transferGB*trafficGB, nil, 0, groupID, planID, nil, expiry))
			mock.ExpectQuery(`(?s)SELECT.*FROM v2_plan WHERE id = \$1 LIMIT 1`).WithArgs(planID).
				WillReturnRows(sqlmock.NewRows([]string{"id", "group_id", "transfer_enable", "device_limit", "speed_limit", "show", "renew", "month_price", "quarter_price", "half_year_price", "year_price", "two_year_price", "three_year_price", "onetime_price", "reset_price", "reset_traffic_method", "capacity_limit"}).
					AddRow(planID, groupID, transferGB, nil, nil, 1, 1, 100, nil, nil, nil, nil, nil, nil, nil, 1, nil))
			u, d := 230, 120
			if tc.wantReset {
				u, d = 0, 0
			}
			mock.ExpectExec(`UPDATE v2_user SET balance =`).
				WithArgs(userID, 0, 0, u, d, transferGB*trafficGB, nil, groupID, planID, nil, sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 1))
			if tc.wantNewAnchor || tc.wantReset {
				mock.ExpectExec(`UPDATE v2_user SET traffic_reset_anchor_at = CASE`).
					WithArgs(userID, tc.wantNewAnchor, sqlmock.AnyArg(), planID, tc.wantReset, sqlmock.AnyArg()).
					WillReturnResult(sqlmock.NewResult(0, 1))
			}
			mock.ExpectExec(`UPDATE v2_order SET status =`).
				WithArgs(orderID, 3, "order-completion-test", sqlmock.AnyArg(), sqlmock.AnyArg()).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()

			svc := NewDBService(tc.cfg, db)
			order := orderRecord{ID: orderID, UserID: userID, PlanID: planID, TradeNo: "order-completion-test", Type: tc.orderType, Period: "month_price"}
			if err := svc.openOrderTx(ctx, tx, &order); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

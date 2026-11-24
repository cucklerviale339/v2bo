package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"forest/go-api/internal/config"
)

func TestNewcomerCouponUsesRegisteredAtForPreviewAndOrder(t *testing.T) {
	const userID int64 = 7
	const couponID int64 = 42
	now := time.Now().Unix()
	for _, tc := range []struct {
		name                                          string
		id, startedAt, endedAt, registeredAt, wantEnd int64
		wantError                                     error
	}{
		{"registration deadline", couponID, now - 3*86400, now + 2*86400, now - 3600, now - 3600 + newcomerCouponSeconds, nil},
		{"coupon ends first", couponID, now - 3*86400, now + 3600, now - 60, now + 3600, nil},
		{"past personal deadline", couponID, now - 3*86400, now + 2*86400, now - newcomerCouponSeconds, 0, ErrCouponExpired},
		{"registered before activity", couponID, now - 120, now + 2*86400, now - 3600, 0, ErrCouponInvalid},
		{"ordinary coupon", couponID + 1, now - 3*86400, now + 2*86400, now - 2*86400, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			service := NewDBService(config.Config{NewcomerCouponID: couponID}, db)
			ctx := context.Background()
			expectRegistration := func() {
				if tc.id == couponID {
					mock.ExpectQuery(`SELECT created_at FROM v2_user WHERE id = \$1`).WithArgs(userID).
						WillReturnRows(sqlmock.NewRows([]string{"created_at"}).AddRow(tc.registeredAt))
				}
			}

			mock.ExpectBegin()
			if tc.id == couponID {
				mock.ExpectQuery(`SELECT code FROM v2_coupon WHERE id = \$1 FOR UPDATE`).WithArgs(couponID).
					WillReturnRows(sqlmock.NewRows([]string{"code"}).AddRow("test-coupon"))
			}
			mock.ExpectQuery(`(?s)SELECT\s+id, type, value, "show",.*FROM v2_coupon.*WHERE code = \$1`).WithArgs("test-coupon").
				WillReturnRows(sqlmock.NewRows([]string{"id", "type", "value", "show", "limit_use", "limit_use_with_user", "limit_plan_ids", "limit_period", "started_at", "ended_at"}).
					AddRow(tc.id, 2, 20, 1, nil, nil, nil, nil, tc.startedAt, tc.endedAt))
			expectRegistration()
			mock.ExpectRollback()
			var preview map[string]any
			if tc.id == couponID {
				preview, err = service.CheckNewcomerCoupon(ctx, userID)
			} else {
				preview, err = service.CheckCoupon(ctx, userID, "test-coupon", nil)
			}
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("preview error = %v, want %v", err, tc.wantError)
			}
			if tc.wantEnd > 0 {
				if preview["code"] != "test-coupon" {
					t.Fatal("preview did not return the selected coupon code")
				}
				if preview["personal_ended_at"] != tc.wantEnd {
					t.Fatalf("preview personal deadline = %v, want %d", preview["personal_ended_at"], tc.wantEnd)
				}
				if serverNow, ok := preview["server_now"].(int64); !ok || serverNow < now || serverNow > tc.wantEnd {
					t.Fatalf("invalid preview server time: %v", preview["server_now"])
				}
			} else if _, present := preview["personal_ended_at"]; present {
				t.Fatal("unexpected personal deadline")
			}

			mock.ExpectBegin()
			expectRegistration()
			mock.ExpectRollback()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			draft := orderDraft{UserID: userID, PlanID: 1, Period: "month_price", TotalAmount: 1000}
			coupon := couponRecord{ID: tc.id, Type: 2, Value: 20, Show: 1, StartedAt: tc.startedAt, EndedAt: tc.endedAt}
			if err := service.applyCouponTx(ctx, tx, coupon, &draft); !errors.Is(err, tc.wantError) {
				t.Fatalf("order error = %v, want %v", err, tc.wantError)
			}
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			if tc.wantError == nil && (draft.TotalAmount != 800 || !draft.CouponID.Valid) {
				t.Fatalf("coupon discount did not apply: %+v", draft)
			}
			if tc.wantError != nil && (draft.TotalAmount != 1000 || draft.CouponID.Valid) {
				t.Fatalf("ineligible order discounted: %+v", draft)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

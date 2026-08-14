package user

import (
	"database/sql"
	"testing"
	"time"
)

func TestPlanTransferEnableBytesNormalizesWithoutDoubleMultiplying(t *testing.T) {
	if got := planTransferEnableBytes(trafficGB); got != trafficGB {
		t.Fatalf("expected byte-valued plan transfer to stay %d, got %d", trafficGB, got)
	}
}

func TestPlanTransferEnableGBConvertsToBytes(t *testing.T) {
	if got := planTransferEnableBytes(2); got != 2*trafficGB {
		t.Fatalf("expected GB-valued plan transfer to convert to %d, got %d", 2*trafficGB, got)
	}
}

func TestOrderResetsTrafficForNewPurchaseAndResetPackage(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.Local)
	tests := []orderRecord{
		{Type: 1, Period: "month_price"},
		{Type: 4, Period: "reset_price"},
		{Type: 1, Period: "onetime_price"},
	}
	for _, order := range tests {
		if !orderResetsTraffic(order, sql.NullInt64{}, now) {
			t.Fatalf("expected order type=%d period=%s to reset traffic", order.Type, order.Period)
		}
	}
}

func TestOrderResetsTrafficForRenewalOnlyOnExpiryDay(t *testing.T) {
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.Local)
	order := orderRecord{Type: 2, Period: "month_price"}

	if orderResetsTraffic(order, sql.NullInt64{Int64: now.AddDate(0, 1, 0).Unix(), Valid: true}, now) {
		t.Fatal("expected early renewal to keep current traffic")
	}
	if !orderResetsTraffic(order, sql.NullInt64{Int64: now.Add(3 * time.Hour).Unix(), Valid: true}, now) {
		t.Fatal("expected expiry-day renewal to reset traffic")
	}
}

func TestTrafficResetMonthlyCycleUsesOrderAnchorInsteadOfExpiry(t *testing.T) {
	loc := time.FixedZone("UTC+8", 8*60*60)
	now := time.Date(2026, time.August, 15, 0, 5, 0, 0, loc)
	orderAnchorAt := time.Date(2026, time.June, 15, 12, 0, 0, 0, loc).Unix()
	expiredAt := time.Date(2027, time.September, 22, 12, 0, 0, 0, loc).Unix()

	cycle, ok := trafficResetCurrentCycle(7, 1, orderAnchorAt, expiredAt, now)
	if !ok {
		t.Fatal("expected monthly cycle")
	}
	want := time.Date(2026, time.August, 15, 0, 0, 0, 0, loc).Unix()
	if cycle.StartAt != want {
		t.Fatalf("expected order-day cycle %d, got %d", want, cycle.StartAt)
	}
}

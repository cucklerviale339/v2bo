package payment

import "testing"

func TestEPayProFormUsesPaymentTypeSelect(t *testing.T) {
	form, ok := GatewayForm("EPayPro")
	if !ok {
		t.Fatal("expected EPayPro gateway form")
	}

	field, ok := form["type"]
	if !ok {
		t.Fatal("expected EPayPro TYPE field")
	}
	if field.Type != "select" {
		t.Fatalf("expected TYPE field to be a select, got %q", field.Type)
	}
	if len(field.Options) != 2 || field.Options[0].Value != "alipay" || field.Options[1].Value != "wxpay" {
		t.Fatalf("unexpected TYPE options: %#v", field.Options)
	}
}

func TestAlipayProductNameDefaultsToForest(t *testing.T) {
	if got := alipayProductName(map[string]string{}); got != "Forest - 订阅" {
		t.Fatalf("expected default product name to use Forest branding, got %q", got)
	}
}

func TestAlipayProductNameAllowsOverride(t *testing.T) {
	if got := alipayProductName(map[string]string{"product_name": "Custom Name"}); got != "Custom Name" {
		t.Fatalf("expected explicit product name override, got %q", got)
	}
}

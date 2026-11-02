package admin

import "testing"

func TestNormalizeBulkMailSubjectAddsBrandWithoutChangingWording(t *testing.T) {
	if got := normalizeBulkMailSubject("请更新一下", "GearFlow Cloud"); got != "GearFlow Cloud｜请更新一下" {
		t.Fatalf("unexpected subject: %q", got)
	}
	if got := normalizeBulkMailSubject("GearFlow Cloud 服务通知", "GearFlow Cloud"); got != "GearFlow Cloud 服务通知" {
		t.Fatalf("branded subject changed: %q", got)
	}
	if got := normalizeBulkMailSubject("通知\r\n", "GearFlow Cloud"); got != "GearFlow Cloud｜通知" {
		t.Fatalf("header newline not neutralized: %q", got)
	}
}

func TestNormalizeBulkMailContentAddsContextOnlyForKnownGenericText(t *testing.T) {
	got := normalizeBulkMailContent("请更新一下", "GearFlow Cloud")
	want := "GearFlow Cloud 服务通知\n\n通知内容：\n请更新一下\n\n如需帮助，请登录网站后通过站内工单联系我们。"
	if got != want {
		t.Fatalf("unexpected generic content: %q", got)
	}
	if got := normalizeBulkMailContent("客户端将于周五升级，请提前保存配置。", "GearFlow Cloud"); got != "客户端将于周五升级，请提前保存配置。" {
		t.Fatalf("specific content changed: %q", got)
	}
}

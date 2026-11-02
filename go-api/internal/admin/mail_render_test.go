package admin

import (
	"os"
	"path/filepath"
	"testing"
)

func adminMailTestTemplate(t *testing.T, source string) bulkMailConfig {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "resources", "views", "mail", "GearFlow")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notify.blade.php"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	oldRoot := adminProjectRoot
	adminProjectRoot = root
	t.Cleanup(func() { adminProjectRoot = oldRoot })
	return bulkMailConfig{template: "GearFlow", appName: "GearFlow & <Cloud>"}
}

func TestRenderAdminBulkMailBodyPreservesTrustedCampaignHTML(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<h1>{{$name}}</h1><div>{!! $content_html !!}</div>`)
	content := `<p>版本 3.2.1 &amp; 季付优惠</p>` + "\r\n" + `<a href="https://example.com/upgrade">升级</a><br />`
	want := `<h1>GearFlow &amp; &lt;Cloud&gt;</h1><div><p>版本 3.2.1 &amp; 季付优惠</p>` + "\r\n" + `<a href="https://example.com/upgrade">升级</a><br /></div>`
	if got := renderAdminBulkMailBody(cfg, content); got != want {
		t.Fatalf("campaign HTML or escaped brand changed:\ngot  %s\nwant %s", got, want)
	}
}

func TestRenderAdminBulkMailBodyPreservesMultilineHTMLAttributes(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<div>{!! $content_html !!}</div>`)
	content := "<a\r\n" + `href="https://example.com/upgrade"` + "\n" + `style="color:#2563eb;` + "\n" + `text-decoration:none;">升级</a>`
	if got := renderAdminBulkMailBody(cfg, content); got != "<div>"+content+"</div>" {
		t.Fatalf("line breaks inside HTML tags or attributes changed: got %q, want %q", got, "<div>"+content+"</div>")
	}
}

func TestRenderAdminBulkMailBodyEscapesTextWithoutHTMLStartTags(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<div>{!! $content_html !!}</div>`)
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"ampersand and line endings", "A & B\r\n第二行\r第三行\n第四行", "A &amp; B<br>第二行<br>第三行<br>第四行"},
		{"comparison", "2 < 3 > 1", "2 &lt; 3 &gt; 1"},
		{"already encoded text", "&lt;p&gt;A &amp; B&lt;/p&gt;", "&amp;lt;p&amp;gt;A &amp;amp; B&amp;lt;/p&amp;gt;"},
		{"comment only", "<!-- note -->", "&lt;!-- note --&gt;"},
		{"closing tag only", "</p>", "&lt;/p&gt;"},
		{"doctype only", "<!doctype html>", "&lt;!doctype html&gt;"},
		{"unfinished tag", "<p", "&lt;p"},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renderAdminBulkMailBody(cfg, tc.content); got != "<div>"+tc.want+"</div>" {
				t.Fatalf("plain text was not safely rendered: got %q, want %q", got, "<div>"+tc.want+"</div>")
			}
		})
	}
}

func TestRenderAdminBulkMailBodyRecognizesSelfClosingHTML(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<div>{!! $content_html !!}</div>`)
	if got := renderAdminBulkMailBody(cfg, `第一行<br />第二行`); got != `<div>第一行<br />第二行</div>` {
		t.Fatalf("self-closing HTML was escaped: %q", got)
	}
}

func TestRenderAdminMailBodyEscapesOrdinaryNotificationHTML(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<h1>{{$name}}</h1><div>{!! $content_html !!}</div>`)
	content := `<a href="https://example.invalid">工单用户输入</a> & <img src=x onerror=alert(1)>` + "\r\n下一行"
	want := `<h1>GearFlow &amp; &lt;Cloud&gt;</h1><div>&lt;a href=&#34;https://example.invalid&#34;&gt;工单用户输入&lt;/a&gt; &amp; &lt;img src=x onerror=alert(1)&gt;<br>下一行</div>`
	if got := renderAdminMailBody(cfg, "notify", content, nil); got != want {
		t.Fatalf("ordinary notification must not render user HTML:\ngot  %s\nwant %s", got, want)
	}
}

func TestRenderAdminMailBodyUsesFinalContentAndPreservesExplicitHTML(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<div>{!! $content_html !!}</div>`)
	if got := renderAdminMailBody(cfg, "notify", "fallback", map[string]string{"content": "<b>override</b>\nA & B"}); got != `<div>&lt;b&gt;override&lt;/b&gt;<br>A &amp; B</div>` {
		t.Fatalf("content_html must use final content: %q", got)
	}
	if got := renderAdminMailBody(cfg, "notify", "fallback", map[string]string{"content_html": "<p>explicit</p>\n"}); got != "<div><p>explicit</p>\n</div>" {
		t.Fatalf("explicit content_html was changed: %q", got)
	}
	if got := renderAdminMailBody(cfg, "notify", "fallback", map[string]string{"content_html": ""}); got != "<div></div>" {
		t.Fatalf("explicit empty content_html was replaced: %q", got)
	}
}

func TestRenderAdminMailBodyPreservesLegacyContentVariable(t *testing.T) {
	cfg := adminMailTestTemplate(t, `<div>{!! $content !!}</div><p>{{$content}}</p>`)
	content := `<b>A & B</b>`
	want := `<div><b>A & B</b></div><p>&lt;b&gt;A &amp; B&lt;/b&gt;</p>`
	if got := renderAdminMailBody(cfg, "notify", content, nil); got != want {
		t.Fatalf("legacy content rendering changed: got %q, want %q", got, want)
	}
}

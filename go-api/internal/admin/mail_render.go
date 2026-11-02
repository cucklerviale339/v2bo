package admin

import (
	"fmt"
	"html"
	"strings"

	"forest/go-api/internal/platform/mailtmpl"

	nethtml "golang.org/x/net/html"
)

func renderAdminMailBody(cfg bulkMailConfig, templateName, fallbackBody string, values map[string]string) string {
	if values == nil {
		values = map[string]string{}
	}
	if _, ok := values["name"]; !ok {
		values["name"] = cfg.appName
	}
	if _, ok := values["url"]; !ok {
		values["url"] = cfg.appURL
	}
	if _, ok := values["logo"]; !ok {
		values["logo"] = cfg.logo
	}
	if _, ok := values["content"]; !ok {
		values["content"] = fallbackBody
	}
	if _, ok := values["content_html"]; !ok {
		values["content_html"] = adminMailNL2BR(html.EscapeString(values["content"]))
	}

	body, _, err := mailtmpl.Render(adminProjectRoot, cfg.template, templateName, values)
	if err != nil {
		return fallbackBody
	}
	return strings.TrimSpace(body)
}

// renderAdminBulkMailBody accepts HTML authored by trusted administrators only.
// The tokenizer detects markup; it does not sanitize untrusted HTML. Ordinary
// notifications, including ticket text, must use renderAdminMailBody instead.
func renderAdminBulkMailBody(cfg bulkMailConfig, content string) string {
	content = normalizeBulkMailContent(content, cfg.appName)
	contentHTML := adminMailNL2BR(html.EscapeString(content))
	if adminMailHasHTML(content) {
		contentHTML = content
	}
	return renderAdminMailBody(cfg, "notify", content, map[string]string{
		"content_html": contentHTML,
	})
}

func adminMailHasHTML(content string) bool {
	tokenizer := nethtml.NewTokenizer(strings.NewReader(content))
	for {
		switch tokenizer.Next() {
		case nethtml.StartTagToken, nethtml.SelfClosingTagToken:
			return true
		case nethtml.ErrorToken:
			return false
		}
	}
}

func adminMailNL2BR(content string) string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	return strings.ReplaceAll(content, "\n", "<br>")
}

func buildSMTPHeaderFrom(from, fromName string) string {
	from = strings.TrimSpace(from)
	fromName = strings.TrimSpace(fromName)
	if fromName == "" {
		return from
	}
	return fmt.Sprintf("%s <%s>", fromName, from)
}

func adminSMTPContentType(body string) string {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<body") || strings.Contains(lower, "<div") || strings.Contains(lower, "<table") {
		return "text/html; charset=UTF-8"
	}
	return "text/plain; charset=UTF-8"
}

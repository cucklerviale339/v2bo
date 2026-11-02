package mailwire

import (
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildHTMLMessageIncludesPlainTextAlternativeAndEncodedHeaders(t *testing.T) {
	body := `<!doctype html><html><head><title>忽略标题</title></head><body><h1>账户通知</h1><p>你好，用户</p><a href="https://example.com">进入 GearFlow Cloud</a></body></html>`
	raw := Build("notice@example.com", "GearFlow 云", "user@example.net", "GearFlow Cloud 通知", "id@example.com", time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC), body)
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if got := message.Header.Get("Subject"); !strings.Contains(got, "=?UTF-8?") {
		t.Fatalf("subject should be RFC 2047 encoded, got %q", got)
	}
	if decoded, err := (&mime.WordDecoder{}).DecodeHeader(message.Header.Get("Subject")); err != nil || decoded != "GearFlow Cloud 通知" {
		t.Fatalf("decoded subject = %q, err = %v", decoded, err)
	}
	if !strings.Contains(strings.ToLower(message.Header.Get("From")), "=?utf-8?") {
		t.Fatalf("from display name should be RFC 2047 encoded, got %q", message.Header.Get("From"))
	}
	from, err := mail.ParseAddress(message.Header.Get("From"))
	if err != nil || from.Name != "GearFlow 云" {
		t.Fatalf("decoded from = %#v, err = %v", from, err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("content type = %q, err = %v", mediaType, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var plain, rendered string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := io.ReadAll(quotedprintable.NewReader(part))
		if err != nil {
			t.Fatal(err)
		}
		switch part.Header.Get("Content-Type") {
		case "text/plain; charset=UTF-8":
			plain = string(decoded)
		case "text/html; charset=UTF-8":
			rendered = string(decoded)
		}
	}
	if !strings.Contains(plain, "账户通知") || !strings.Contains(plain, "你好，用户") || !strings.Contains(plain, "https://example.com") || strings.Contains(plain, "忽略标题") {
		t.Fatalf("unexpected plain text alternative: %q", plain)
	}
	if !strings.Contains(rendered, "<html") {
		t.Fatalf("HTML part missing: %q", rendered)
	}
}

func TestBuildPlainMessagePreservesUnicodeAndNeutralizesSubjectNewlines(t *testing.T) {
	body := "A & B\r\n中文正文"
	raw := Build("notice@example.com", "", "user@example.net", "通知\r\nBcc: other@example.org", "id@example.com", time.Now(), body)
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if message.Header.Get("Bcc") != "" {
		t.Fatal("subject injected a header")
	}
	if got := message.Header.Get("Content-Type"); got != "text/plain; charset=UTF-8" {
		t.Fatalf("unexpected content type: %q", got)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(message.Body))
	if err != nil || string(decoded) != body {
		t.Fatalf("plain body changed: %q, err=%v", decoded, err)
	}
}

func TestBuildRetainsHTMLFragmentSupport(t *testing.T) {
	raw := Build("notice@example.com", "", "user@example.net", "通知", "id@example.com", time.Now(), "<div>原有 HTML 片段</div>")
	message, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, _, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("HTML fragment became plain text: %q, err=%v", mediaType, err)
	}
}

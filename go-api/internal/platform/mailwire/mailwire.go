package mailwire

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"

	xhtml "golang.org/x/net/html"
)

func Build(from, fromName, to, subject, messageID string, sentAt time.Time, body string) []byte {
	var message bytes.Buffer
	fromHeader := strings.TrimSpace(from)
	if strings.TrimSpace(fromName) != "" {
		fromHeader = (&mail.Address{Name: strings.TrimSpace(fromName), Address: fromHeader}).String()
	}
	toHeader := strings.TrimSpace(to)
	if address, err := mail.ParseAddress(toHeader); err == nil {
		toHeader = address.String()
	}
	fmt.Fprintf(&message, "To: %s\r\n", toHeader)
	fmt.Fprintf(&message, "From: %s\r\n", fromHeader)
	subject = strings.NewReplacer("\r", " ", "\n", " ").Replace(subject)
	fmt.Fprintf(&message, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", subject))
	fmt.Fprintf(&message, "Date: %s\r\n", sentAt.Format(time.RFC1123Z))
	fmt.Fprintf(&message, "Message-ID: <%s>\r\n", messageID)
	message.WriteString("MIME-Version: 1.0\r\n")

	if !isHTML(body) {
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		writeQuotedPrintable(&message, body)
		return message.Bytes()
	}

	var parts bytes.Buffer
	writer := multipart.NewWriter(&parts)
	writePart(writer, "text/plain; charset=UTF-8", htmlToText(body))
	writePart(writer, "text/html; charset=UTF-8", body)
	_ = writer.Close()
	fmt.Fprintf(&message, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", writer.Boundary())
	message.Write(parts.Bytes())
	return message.Bytes()
}

func isHTML(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<html") || strings.Contains(lower, "<body") || strings.Contains(lower, "<div") || strings.Contains(lower, "<table")
}

func writePart(writer *multipart.Writer, contentType, body string) {
	header := make(textproto.MIMEHeader)
	header.Set("Content-Type", contentType)
	header.Set("Content-Transfer-Encoding", "quoted-printable")
	part, err := writer.CreatePart(header)
	if err != nil {
		return
	}
	writeQuotedPrintable(part, body)
}

func writeQuotedPrintable(writer io.Writer, body string) {
	encoder := quotedprintable.NewWriter(writer)
	_, _ = io.WriteString(encoder, body)
	_ = encoder.Close()
}

func htmlToText(body string) string {
	tokenizer := xhtml.NewTokenizer(strings.NewReader(body))
	var text strings.Builder
	var skipped []string
	type anchor struct {
		href  string
		start int
	}
	var anchors []anchor
	for {
		tokenType := tokenizer.Next()
		switch tokenType {
		case xhtml.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return normalizeText(text.String())
			}
			return normalizeText(text.String())
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			token := tokenizer.Token()
			switch strings.ToLower(token.Data) {
			case "head", "style", "script", "title":
				skipped = append(skipped, strings.ToLower(token.Data))
			case "br", "hr":
				if len(skipped) == 0 {
					text.WriteByte('\n')
				}
			case "p", "div", "tr", "h1", "h2", "h3", "li":
				if len(skipped) == 0 {
					text.WriteByte('\n')
				}
			case "a":
				if len(skipped) == 0 {
					link := anchor{start: text.Len()}
					for _, attribute := range token.Attr {
						if strings.EqualFold(attribute.Key, "href") {
							link.href = attribute.Val
							break
						}
					}
					anchors = append(anchors, link)
				}
			}
		case xhtml.EndTagToken:
			token := tokenizer.Token()
			tag := strings.ToLower(token.Data)
			if tag == "a" && len(anchors) > 0 {
				link := anchors[len(anchors)-1]
				anchors = anchors[:len(anchors)-1]
				if link.href != "" && len(skipped) == 0 {
					label := strings.TrimSpace(text.String()[link.start:])
					if !strings.Contains(label, link.href) {
						text.WriteString(" (" + link.href + ")")
					}
				}
			}
			if len(skipped) > 0 && skipped[len(skipped)-1] == tag {
				skipped = skipped[:len(skipped)-1]
			}
			switch tag {
			case "p", "div", "tr", "h1", "h2", "h3", "li":
				if len(skipped) == 0 {
					text.WriteByte('\n')
				}
			}
		case xhtml.TextToken:
			if len(skipped) == 0 {
				text.WriteString(html.UnescapeString(string(tokenizer.Text())))
			}
		}
	}
}

func normalizeText(value string) string {
	lines := strings.Split(strings.ReplaceAll(value, "\r", ""), "\n")
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.Join(strings.Fields(line), " ")
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

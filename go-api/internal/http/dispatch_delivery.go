package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"forest/go-api/internal/subscribelink"
	usersvc "forest/go-api/internal/user"
	"gopkg.in/yaml.v3"
)

type dispatchDeliveryRecorder interface {
	RecordInvestigationDelivery(context.Context, int64, []usersvc.InvestigationDelivery, int64) error
	MarkInvestigationDeliveryFailure(context.Context) error
}
type dispatchDeliveryWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
	failed bool
}

func (w *dispatchDeliveryWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}
func (w *dispatchDeliveryWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	n, err := w.ResponseWriter.Write(p)
	if err != nil || n != len(p) {
		w.failed = true
	}
	if w.body.Len()+len(p) <= 16<<20 {
		w.body.Write(p)
	} else {
		w.failed = true
	}
	return n, err
}
func (w *dispatchDeliveryWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func trackDispatchDelivery(w http.ResponseWriter, r *http.Request, service usersvc.Service, userID int64, servers []map[string]any) (http.ResponseWriter, func()) {
	recorder, ok := service.(dispatchDeliveryRecorder)
	if !ok {
		return w, func() {}
	}
	entries := []usersvc.InvestigationDelivery{}
	seen := map[int64]bool{}
	seenOrdinary := map[string]bool{}
	for _, server := range servers {
		if subscribelink.IsExtra(server) {
			continue
		}
		if h, ok := server["host"].(usersvc.InvestigationHost); ok && !seen[h.GroupID] {
			seen[h.GroupID] = true
			entries = append(entries, usersvc.InvestigationDelivery{GroupID: h.GroupID, Generation: h.Generation, Host: h.Value})
		} else if !ok {
			host := usersvc.NormalizeDispatchHost(fmt.Sprint(server["host"]))
			if host != "" && host != "<nil>" && !seenOrdinary[host] {
				seenOrdinary[host] = true
				entries = append(entries, usersvc.InvestigationDelivery{Host: host})
			}
		}
	}
	if len(entries) == 0 {
		return w, func() {}
	}
	writer := &dispatchDeliveryWriter{ResponseWriter: w}
	return writer, func() {
		if recovered := recover(); recovered != nil {
			panic(recovered)
		}
		if writer.failed || writer.status != 200 || writer.body.Len() == 0 {
			return
		}
		hosts := deliveredEndpointHosts(writer.body.Bytes())
		actual := []usersvc.InvestigationDelivery{}
		for _, e := range entries {
			if hosts[usersvc.NormalizeDispatchHost(e.Host)] {
				actual = append(actual, e)
			}
		}
		if len(actual) == 0 {
			return
		}
		// Do not inherit a disconnected request's cancellation after its response
		// was successfully written. Bound bookkeeping independently.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Second)
		defer cancel()
		if err := recorder.RecordInvestigationDelivery(ctx, userID, actual, time.Now().Unix()); err != nil {
			_ = recorder.MarkInvestigationDeliveryFailure(ctx)
		}
	}
}

// Read endpoint fields, never substring-search comments, SNI, WS Host or node
// names. Supports JSON/YAML profiles, URI/base64 subscriptions and INI clients.
func deliveredEndpointHosts(body []byte) map[string]bool {
	out := map[string]bool{}
	add := func(v any) {
		s := strings.TrimSpace(fmt.Sprint(v))
		if s != "" && s != "<nil>" {
			out[usersvc.NormalizeDispatchHost(s)] = true
		}
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if _, ok := x["port"]; ok {
				if h, ok := x["add"]; ok {
					add(h)
				} else if h, ok := x["host"]; ok {
					add(h)
				}
			}
			if h, ok := x["server"]; ok {
				if _, ok := x["port"]; ok {
					add(h)
				} else if _, ok := x["server_port"]; ok {
					add(h)
				} else if _, ok := x["server_ports"]; ok {
					add(h)
				}
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	decode := func(s string) []byte {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(strings.TrimSpace(s)); e == nil {
				return b
			}
		}
		return nil
	}
	var parse func([]byte, int)
	parse = func(b []byte, depth int) {
		if depth > 2 || len(b) == 0 {
			return
		}
		var value any
		if json.Unmarshal(b, &value) == nil {
			walk(value)
		} else if yaml.Unmarshal(b, &value) == nil {
			walk(value)
		}
		text := strings.TrimSpace(string(b))
		if !strings.ContainsAny(text, "\n :{[") {
			if raw := decode(text); len(raw) > 0 {
				parse(raw, depth+1)
			}
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
				continue
			}
			if strings.HasPrefix(line, "vmess://") {
				decoded := decode(strings.SplitN(strings.TrimPrefix(line, "vmess://"), "?", 2)[0])
				parse(decoded, depth+1)
				if u, err := url.Parse("vmess://" + string(decoded)); err == nil && u.Hostname() != "" && u.Port() != "" {
					add(u.Hostname())
				}
			}
			if strings.HasPrefix(line, "ss://") {
				if node, err := subscribelink.Parse(line); err == nil {
					add(node["host"])
				}
			}
			if u, err := url.Parse(line); err == nil && u.Hostname() != "" && u.Port() != "" {
				switch u.Scheme {
				case "ss", "vmess", "vless", "trojan", "tuic", "hysteria", "hysteria2", "hy2", "anytls", "juicity", "mieru":
					add(u.Hostname())
				}
				continue
			}
			left, right, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			_ = left
			parts := strings.Split(right, ",")
			if len(parts) >= 3 {
				kind := strings.ToLower(strings.TrimSpace(parts[0]))
				switch kind {
				case "ss", "shadowsocks", "vmess", "vless", "trojan", "hysteria2", "anytls":
					add(strings.TrimSpace(parts[1]))
				}
			}
			if len(parts) > 0 {
				if host, _, err := net.SplitHostPort(strings.TrimSpace(parts[0])); err == nil {
					add(host)
				}
			}
		}
	}
	parse(body, 0)
	return out
}

var _ io.Writer = (*dispatchDeliveryWriter)(nil)

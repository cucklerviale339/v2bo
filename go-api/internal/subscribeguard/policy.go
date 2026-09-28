package subscribeguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Rule struct {
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Token     string `json:"token,omitempty"`
	Note      string `json:"note"`
	ExpiresAt int64  `json:"expires_at"`
}

type Policy struct {
	Revision       int64    `json:"revision"`
	Mode           string   `json:"mode"`
	IPLimit        int64    `json:"ip_limit"`
	TokenLimit     int64    `json:"token_limit"`
	BlockEmptyUA   bool     `json:"block_empty_ua"`
	BlockCrawlerUA bool     `json:"block_crawler_ua"`
	KeepDays       int64    `json:"keep_days"`
	TrustedProxies []string `json:"trusted_proxies"`
	Rules          []Rule   `json:"rules"`
	TokenBlacklist []string `json:"token_blacklist"`
	tokenHashes    map[string]bool
}

func DefaultPolicy() Policy {
	return Policy{Mode: "off", KeepDays: 7, TrustedProxies: []string{}, Rules: []Rule{}, TokenBlacklist: []string{}}
}

func Fingerprint(key, token string) string {
	if key == "" || strings.TrimSpace(token) == "" {
		return ""
	}
	digest := hmac.New(sha256.New, []byte(key))
	digest.Write([]byte("subscribe-guard:v1:" + strings.TrimSpace(token)))
	return hex.EncodeToString(digest.Sum(nil))
}

func (policy *Policy) Validate(key string) error {
	if policy.Mode != "off" && policy.Mode != "observe" && policy.Mode != "enforce" {
		return errors.New("防护模式无效")
	}
	if policy.Mode != "off" && key == "" {
		return errors.New("请先配置 APP_KEY")
	}
	if policy.IPLimit < 0 || policy.IPLimit > 100000 || policy.TokenLimit < 0 || policy.TokenLimit > 100000 {
		return errors.New("每分钟限额须为 0-100000，0 表示不限流")
	}
	if policy.KeepDays < 1 || policy.KeepDays > 365 || len(policy.Rules)+len(policy.TokenBlacklist) > 1000 || len(policy.TrustedProxies) > 100 {
		return errors.New("保留期须为 1-365 天，规则最多 1000 条，代理网段最多 100 条")
	}
	policy.tokenHashes = map[string]bool{}
	for index, token := range policy.TokenBlacklist {
		token = strings.TrimSpace(token)
		if token == "" || len(token) > 4096 || strings.ContainsAny(token, "\r\n") || key == "" {
			return errors.New("订阅 Token 无效或缺少 APP_KEY")
		}
		policy.TokenBlacklist[index] = token
		hash := Fingerprint(key, token)
		if policy.tokenHashes[hash] {
			return errors.New("存在重复的订阅 Token")
		}
		policy.tokenHashes[hash] = true
	}
	for index, value := range policy.TrustedProxies {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil || prefix.Bits() == 0 {
			return errors.New("可信代理必须是明确的 CIDR 网段，不能信任全部地址")
		}
		policy.TrustedProxies[index] = prefix.Masked().String()
	}
	seen := map[string]bool{}
	for index := range policy.Rules {
		rule := &policy.Rules[index]
		rule.Value = strings.TrimSpace(rule.Value)
		rule.Note = strings.TrimSpace(rule.Note)
		if len(rule.Note) > 255 || rule.ExpiresAt < 0 {
			return errors.New("规则备注或到期时间无效")
		}
		switch rule.Kind {
		case "ip_allow", "ip_block":
			if address, err := netip.ParseAddr(rule.Value); err == nil {
				rule.Value = address.Unmap().String()
			} else if prefix, err := netip.ParsePrefix(rule.Value); err == nil && prefix.Bits() > 0 {
				rule.Value = prefix.Masked().String()
			} else {
				return errors.New("IP 规则必须是 IP 或 CIDR，不能匹配全部地址")
			}
		case "ua_allow", "ua_block":
			rule.Value = strings.ToLower(rule.Value)
			if len(rule.Value) == 0 || len(rule.Value) > 512 {
				return errors.New("UA 关键词不能为空且不得超过 512 字节")
			}
		case "token_block":
			rule.Value = strings.ToLower(rule.Value)
			if rule.Token != "" {
				if key == "" || len(rule.Token) > 4096 {
					return errors.New("Token 无效或缺少 APP_KEY")
				}
				rule.Value = Fingerprint(key, rule.Token)
			}
			digest, err := hex.DecodeString(rule.Value)
			if err != nil || len(digest) != sha256.Size {
				return errors.New("Token 指纹无效，请输入原始 Token 或从请求记录添加")
			}
		case "user_block":
			userID, err := strconv.ParseInt(rule.Value, 10, 32)
			if err != nil || userID <= 0 {
				return errors.New("用户 ID 无效")
			}
			rule.Value = strconv.FormatInt(userID, 10)
		default:
			return errors.New("规则类型无效")
		}
		rule.Token = ""
		identity := rule.Kind + ":" + rule.Value
		if seen[identity] {
			return fmt.Errorf("存在重复的 %s 规则", rule.Kind)
		}
		seen[identity] = true
	}
	return nil
}

func (policy Policy) Match(kind, value string, now time.Time) bool {
	if value == "" {
		return false
	}
	for _, rule := range policy.Rules {
		if rule.Kind != kind || (rule.ExpiresAt > 0 && rule.ExpiresAt <= now.Unix()) {
			continue
		}
		switch kind {
		case "ip_allow", "ip_block":
			if IPMatches(rule.Value, value) {
				return true
			}
		case "ua_allow", "ua_block":
			if strings.Contains(strings.ToLower(value), rule.Value) {
				return true
			}
		default:
			if value == rule.Value {
				return true
			}
		}
	}
	return false
}

func (policy Policy) Reason(ip, tokenHash, userAgent string, now time.Time) string {
	if policy.tokenHashes[tokenHash] || policy.Match("token_block", tokenHash, now) {
		return "token"
	}
	if policy.Match("ip_allow", ip, now) {
		return ""
	}
	if policy.Match("ip_block", ip, now) {
		return "ip"
	}
	if policy.Match("ua_allow", userAgent, now) {
		return ""
	}
	if policy.BlockEmptyUA && strings.TrimSpace(userAgent) == "" {
		return "empty_ua"
	}
	if policy.Match("ua_block", userAgent, now) {
		return "ua"
	}
	if policy.BlockCrawlerUA && IsCrawlerUA(userAgent) {
		return "crawler_ua"
	}
	return ""
}

func IsCrawlerUA(userAgent string) bool {
	for _, marker := range []string{
		"curl", "wget", "httpie", "aria2", "python", "aiohttp", "urllib", "requests/",
		"go-http-client", "java/", "okhttp", "apache-httpclient", "httpclient", "libwww-perl", "mechanize",
		"scrapy", "spider", "crawler", "bot/",
	} {
		if strings.Contains(strings.ToLower(userAgent), marker) {
			return true
		}
	}
	return false
}

func IPMatches(rule, value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	if prefix, err := netip.ParsePrefix(rule); err == nil {
		return prefix.Contains(address.Unmap())
	}
	other, err := netip.ParseAddr(rule)
	return err == nil && other.Unmap() == address.Unmap()
}

func ClientIP(request *http.Request, proxies []string) string {
	if len(proxies) == 0 {
		proxies = []string{"127.0.0.1/32", "::1/128"}
	}
	peer := request.RemoteAddr
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
	if err != nil {
		return ""
	}
	peer = address.Unmap().String()
	trusted := func(value string) bool {
		for _, prefix := range proxies {
			if IPMatches(prefix, value) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return peer
	}
	values := request.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		values = request.Header.Values("X-Real-IP")
		if len(values) == 1 {
			if parsed, err := netip.ParseAddr(strings.TrimSpace(values[0])); err == nil {
				return parsed.Unmap().String()
			}
		}
		return peer
	}
	forwarded := strings.Split(strings.Join(values, ","), ",")
	if len(forwarded) > 32 {
		return peer
	}
	current := peer
	for index := len(forwarded) - 1; index >= 0; index-- {
		if !trusted(current) {
			return current
		}
		parsed, err := netip.ParseAddr(strings.TrimSpace(forwarded[index]))
		if err != nil {
			return peer
		}
		current = parsed.Unmap().String()
	}
	return current
}

func CleanUA(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, ""))
	if len(value) > 2048 {
		value = value[:2048]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
	}
	return value
}

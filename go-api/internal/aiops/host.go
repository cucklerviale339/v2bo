package aiops

import (
	"errors"
	"net/netip"
	"strings"
)

func NormalizeHost(value string) (string, error) {
	host := strings.TrimSpace(value)
	if host == "" {
		return "", errors.New("地址不能为空")
	}
	if strings.ContainsAny(host, ",，()/?#@[]") || strings.ContainsAny(host, " \t\r\n") {
		return "", errors.New("地址必须是单个域名或 IP")
	}
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		return address.Unmap().String(), nil
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 || strings.Contains(host, ":") {
		return "", errors.New("地址必须是单个域名或 IP")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("地址必须是单个域名或 IP")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", errors.New("地址必须是单个域名或 IP")
			}
		}
	}
	return host, nil
}

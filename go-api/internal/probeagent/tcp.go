package probeagent

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"
)

type CheckResult struct {
	Success    bool
	LatencyMS  *int64
	Error      string
	ResolvedIP string
}

type IPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type TCPChecker struct {
	Resolver IPResolver
	Dialer   interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
}

func (c TCPChecker) Check(ctx context.Context, host string, port int, timeout time.Duration) CheckResult {
	if err := ctx.Err(); err != nil {
		return failedCheck(err, "")
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var addrs []netip.Addr
	if ip := net.ParseIP(host); ip != nil {
		addrs = []netip.Addr{netip.MustParseAddr(ip.String())}
	} else {
		resolver := c.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		var err error
		addrs, err = resolver.LookupNetIP(checkCtx, "ip", host)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(checkCtx.Err(), context.Canceled) {
				return failedCheck(context.Canceled, "")
			}
			return CheckResult{Error: "dns_error"}
		}
		// Resolution can return addresses as its budget expires. No TCP
		// attempt was made, so this is not evidence of a TCP outage.
		if checkCtx.Err() != nil {
			if errors.Is(checkCtx.Err(), context.Canceled) {
				return failedCheck(context.Canceled, "")
			}
			return CheckResult{Error: "dns_error"}
		}
	}
	if len(addrs) == 0 {
		return CheckResult{Error: "dns_error"}
	}
	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	lastIP := ""
	var lastErr error
	for index, addr := range addrs {
		if err := checkCtx.Err(); err != nil {
			return failedCheck(err, lastIP)
		}
		ip := addr.String()
		lastIP = ip
		remaining := time.Until(deadline(checkCtx))
		attemptCtx, attemptCancel := context.WithTimeout(checkCtx, remaining/time.Duration(len(addrs)-index))
		started := time.Now()
		conn, err := dialer.DialContext(attemptCtx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		lastErr = err
		attemptCancel()
		if err == nil {
			_ = conn.Close()
			latency := time.Since(started).Milliseconds()
			return CheckResult{Success: true, LatencyMS: &latency, ResolvedIP: ip}
		}
	}
	if errors.Is(checkCtx.Err(), context.Canceled) {
		return failedCheck(context.Canceled, lastIP)
	}
	return failedCheck(lastErr, lastIP)
}

func deadline(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

func failedCheck(err error, ip string) CheckResult {
	kind := "connect_error"
	var networkErr net.Error
	if errors.Is(err, context.Canceled) {
		kind = "cancelled"
	} else if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &networkErr) && networkErr.Timeout()) {
		kind = "timeout"
	}
	return CheckResult{Error: kind, ResolvedIP: ip}
}

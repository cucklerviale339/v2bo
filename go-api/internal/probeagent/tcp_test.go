package probeagent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type fakeResolver struct {
	addrs []netip.Addr
	err   error
}

type testTCPDialer func(context.Context, string, string) (net.Conn, error)

func (f testTCPDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestTCPCheckerPreservesDialErrorBeforeOuterDeadline(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"wrapped deadline", fmt.Errorf("dial: %w", context.DeadlineExceeded), "timeout"},
		{"network timeout", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ETIMEDOUT}, "timeout"},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, "connect_error"},
		{"unreachable", syscall.ENETUNREACH, "connect_error"},
		{"wrapped cancellation", fmt.Errorf("dial: %w", context.Canceled), "cancelled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := TCPChecker{Dialer: testTCPDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
				if ctx.Err() != nil {
					t.Fatal("outer deadline already expired")
				}
				return nil, tc.err
			})}
			got := checker.Check(context.Background(), "192.0.2.1", 42822, time.Second)
			if got.Success || got.Error != tc.want || got.ResolvedIP != "192.0.2.1" {
				t.Fatal(got)
			}
		})
	}
}

func TestTCPCheckerResolverFailureIsNotTCPTimeout(t *testing.T) {
	for _, err := range []error{errors.New("lookup failed"), context.DeadlineExceeded, &net.DNSError{IsTimeout: true}, nil} {
		got := (TCPChecker{Resolver: fakeResolver{err: err}}).Check(context.Background(), "probe.test", 42822, time.Second)
		if got.Success || got.Error != "dns_error" || got.ResolvedIP != "" {
			t.Fatal(got)
		}
	}
}

func (r fakeResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return r.addrs, r.err
}

func TestTCPCheckerUsesAnyResolvedAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		c, err := listener.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	checker := TCPChecker{Resolver: fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.1")}}}
	result := checker.Check(context.Background(), "probe.test", port, time.Second)
	if !result.Success || result.ResolvedIP != "127.0.0.1" || result.LatencyMS == nil {
		t.Fatalf("result = %#v", result)
	}
}

func TestTCPCheckerClassifiesTimeout(t *testing.T) {
	checker := TCPChecker{}
	result := checker.Check(context.Background(), "203.0.113.1", 9, time.Nanosecond)
	if result.Success || result.Error != "timeout" {
		t.Fatalf("result = %#v", result)
	}
}

type expiredDNSResolver struct{}

func (expiredDNSResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	<-ctx.Done()
	return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
}

func TestTCPCheckerDoesNotCallDNSBudgetExhaustionTCPTimeout(t *testing.T) {
	checker := TCPChecker{Resolver: expiredDNSResolver{}, Dialer: testTCPDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("TCP dial after DNS exhausted check budget")
		return nil, nil
	})}
	got := checker.Check(context.Background(), "probe.test", 42822, time.Millisecond)
	if got.Error != "dns_error" || got.ResolvedIP != "" || got.Success {
		t.Fatal(got)
	}
}

func TestTCPCheckerClassifiesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	checker := TCPChecker{Resolver: fakeResolver{err: errors.New("resolver should not run")}}
	result := checker.Check(ctx, "probe.test", 443, time.Second)
	if result.Success || result.Error != "cancelled" {
		t.Fatalf("result = %#v", result)
	}
}

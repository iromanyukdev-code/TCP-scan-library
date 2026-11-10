package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func scannerForTest(t *testing.T, options ...Option) *Scanner {
	t.Helper()
	s, err := New(options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return s
}

func collect(t *testing.T, ch <-chan Result) []Result {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	var results []Result
	for {
		select {
		case r, ok := <-ch:
			if !ok {
				return results
			}
			results = append(results, r)
		case <-timer.C:
			t.Fatal("result channel did not close")
			return nil
		}
	}
}

func TestPortSets(t *testing.T) {
	p := Union(Range(1, 3), List(3, 5, 5), Range(2, 4))
	if fmt.Sprint(p.values) != "[1 2 3 5 4]" {
		t.Fatal(p.values)
	}
	if len(Range(1, 65535).values) != 65535 {
		t.Fatal("full range")
	}
	s := scannerForTest(t)
	for _, p := range []Ports{List(0), List(-1), List(65536), Range(1000, 1), Range(0, 2), Range(1, 65536), {}, Union(List(1), List(0))} {
		if _, err := s.Scan(context.Background(), []string{"127.0.0.1"}, p); err == nil {
			t.Fatalf("accepted %#v", p)
		}
	}
}

func TestValidation(t *testing.T) {
	for _, option := range []Option{nil, WithConcurrency(0), WithConcurrency(-1), WithConnectTimeout(0)} {
		if _, err := New(option); err == nil {
			t.Fatal("accepted invalid option")
		}
	}
	s := scannerForTest(t)
	for _, hosts := range [][]string{nil, {""}, {" "}, {"127.0.0.999"}, {"a:80"}, {"[::1]"}, {"https://example.com"}, {"a..b"}, {"-a"}, {"a/24"}} {
		if _, err := s.Scan(context.Background(), hosts, List(80)); err == nil {
			t.Fatalf("accepted %q", hosts)
		}
	}
	got, err := normalizeHosts([]string{"EXAMPLE.com.", "example.com", "::1", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1", "127.0.0.1"})
	if err != nil || len(got) != 3 {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := s.Scan(nil, []string{"localhost"}, List(80)); err == nil {
		t.Fatal("nil context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scan(ctx, []string{"localhost"}, List(80)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestClassification(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want State
	}{
		{nil, Open}, {syscall.ECONNREFUSED, Closed}, {context.DeadlineExceeded, Timeout},
		{context.Canceled, Canceled}, {syscall.ENETUNREACH, Unreachable}, {syscall.EHOSTUNREACH, Unreachable},
		{syscall.ENETDOWN, Unreachable}, {syscall.EHOSTDOWN, Unreachable},
		{&net.DNSError{IsTimeout: true}, Timeout}, {&net.DNSError{IsNotFound: true}, Error},
		{errors.New("connection refused"), Error},
	} {
		err := tc.err
		if err != nil {
			err = &net.OpError{Op: "dial", Err: &os.SyscallError{Syscall: "connect", Err: err}}
		}
		if got := classify(err); got != tc.want {
			t.Fatalf("%v: %s != %s", err, got, tc.want)
		}
	}
}

func TestRealTCP(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				if address == "[::1]:0" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			addr := listener.Addr().(*net.TCPAddr)
			peerDone := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					peerDone <- err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				_, err = conn.Read(b[:])
				peerDone <- err
			}()
			s := scannerForTest(t)
			ch, err := s.Scan(context.Background(), []string{addr.IP.String()}, List(addr.Port))
			if err != nil {
				t.Fatal(err)
			}
			results := collect(t, ch)
			if len(results) != 1 || results[0].State != Open || results[0].Err != nil {
				t.Fatal(results)
			}
			if err := <-peerDone; !errors.Is(err, io.EOF) {
				t.Fatalf("connection not closed: %v", err)
			}
			if err := listener.Close(); err != nil {
				t.Fatal(err)
			}
			ch, err = s.Scan(context.Background(), []string{addr.IP.String()}, List(addr.Port))
			if err != nil {
				t.Fatal(err)
			}
			results = collect(t, ch)
			if len(results) != 1 || results[0].State != Closed {
				t.Fatal(results)
			}
		})
	}
}

func TestDNSExpansionAndFailure(t *testing.T) {
	s := scannerForTest(t, WithConcurrency(2))
	var lookups atomic.Int32
	s.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		if host == "bad.test" {
			return nil, &net.DNSError{Name: host, IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:127.0.0.1"), netip.MustParseAddr("::1")}, nil
	}
	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	ch, err := s.Scan(context.Background(), []string{"GOOD.test", "good.test.", "bad.test"}, List(80, 81, 80))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(t, ch)
	if len(results) != 6 || lookups.Load() != 2 {
		t.Fatalf("%v lookups=%d", results, lookups.Load())
	}
	for _, r := range results {
		if r.Host == "bad.test" {
			var dns *net.DNSError
			if r.State != Error || r.IP.IsValid() || !errors.As(r.Err, &dns) {
				t.Fatal(r)
			}
		} else if r.State != Closed || !r.IP.IsValid() {
			t.Fatal(r)
		}
	}
}

func TestGlobalConcurrencyAndCancellation(t *testing.T) {
	s := scannerForTest(t, WithConcurrency(3))
	var active, maximum, calls atomic.Int32
	entered := make(chan struct{}, 3)
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls.Add(1)
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	channels := make([]<-chan Result, 0, 4)
	for i := 0; i < 4; i++ {
		ch, err := s.Scan(ctx, []string{"127.0.0.1"}, Range(1, 65535))
		if err != nil {
			t.Fatal(err)
		}
		channels = append(channels, ch)
	}
	for i := 0; i < 3; i++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("workers not started")
		}
	}
	cancel()
	for _, ch := range channels {
		collect(t, ch)
	}
	if maximum.Load() != 3 || active.Load() != 0 || calls.Load() != 3 {
		t.Fatalf("max=%d active=%d calls=%d", maximum.Load(), active.Load(), calls.Load())
	}
}

func TestTimeouts(t *testing.T) {
	s := scannerForTest(t, WithConnectTimeout(10*time.Millisecond))
	s.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() }
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }
	ch, err := s.Scan(context.Background(), []string{"timeout.test", "127.0.0.1"}, List(80))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(t, ch)
	if len(results) != 2 {
		t.Fatal(results)
	}
	for _, r := range results {
		if r.State != Timeout || r.Duration <= 0 {
			t.Fatal(r)
		}
	}
}

func TestShutdownDrains(t *testing.T) {
	s := scannerForTest(t, WithConcurrency(1))
	started, release := make(chan struct{}), make(chan struct{})
	s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		select {
		case <-release:
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(80))
	if err != nil {
		t.Fatal(err)
	}
	<-started
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		closing := s.closing
		s.mu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shutdown did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(80)); !errors.Is(err, ErrShutdown) {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("early shutdown: %v", err)
	default:
	}
	close(release)
	results := collect(t, ch)
	if len(results) != 1 || results[0].State != Closed {
		t.Fatal(results)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestShutdownWithAbandonedReader(t *testing.T) {
	s := scannerForTest(t, WithConcurrency(2))
	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, Range(1, 65535))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	doneCtx, doneCancel := context.WithTimeout(context.Background(), time.Second)
	defer doneCancel()
	if err := s.Shutdown(doneCtx); err != nil {
		t.Fatal(err)
	}
	collect(t, ch)
}

func TestConcurrentScanAndShutdown(t *testing.T) {
	s := scannerForTest(t, WithConcurrency(2))
	s.dial = func(context.Context, string, string) (net.Conn, error) { return nil, syscall.ECONNREFUSED }
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := s.Scan(context.Background(), []string{"127.0.0.1"}, List(80))
			if errors.Is(err, ErrShutdown) {
				return
			}
			if err != nil {
				t.Error(err)
				return
			}
			for range ch {
			}
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Shutdown(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestForcedShutdownCancelsNetworkOperations(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "blocked.test"} {
		t.Run(host, func(t *testing.T) {
			s := scannerForTest(t, WithConcurrency(1))
			started := make(chan struct{})
			s.dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			s.lookup = func(ctx context.Context, _ string) ([]netip.Addr, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			}
			ch, err := s.Scan(context.Background(), []string{host}, List(80))
			if err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("operation did not start")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := s.Shutdown(ctx); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			cleanup, cleanupCancel := context.WithTimeout(context.Background(), time.Second)
			defer cleanupCancel()
			if err := s.Shutdown(cleanup); err != nil {
				t.Fatal(err)
			}
			for _, r := range collect(t, ch) {
				if r.State != Canceled {
					t.Fatal(r)
				}
			}
		})
	}
}

func TestConnectCanceled(t *testing.T) {
	s := scannerForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	s.dial = func(context.Context, string, string) (net.Conn, error) { cancel(); return nil, context.Canceled }
	r := s.connect(ctx, job{host: "127.0.0.1", ip: netip.MustParseAddr("127.0.0.1"), port: 80})
	if r.State != Canceled || !errors.Is(r.Err, context.Canceled) {
		t.Fatal(r)
	}
}

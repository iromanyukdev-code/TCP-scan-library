package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

var ErrShutdown = errors.New("portscan: scanner is shutting down")

type Option func(*config) error
type config struct {
	concurrency int
	timeout     time.Duration
}

func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("concurrency must be positive")
		}
		c.concurrency = n
		return nil
	}
}

func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("connect timeout must be positive")
		}
		c.timeout = d
		return nil
	}
}

type Scanner struct {
	cfg      config
	slots    chan struct{}
	dial     func(context.Context, string, string) (net.Conn, error)
	lookup   func(context.Context, string) ([]netip.Addr, error)
	lifetime context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closing  bool
	active   sync.WaitGroup
	done     chan struct{}
}

func New(options ...Option) (*Scanner, error) {
	cfg := config{concurrency: 100, timeout: time.Second}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("nil option")
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Scanner{cfg: cfg, slots: make(chan struct{}, cfg.concurrency),
		dial: (&net.Dialer{}).DialContext, lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		lifetime: ctx, cancel: cancel, done: make(chan struct{})}, nil
}

func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	normalized, err := normalizeHosts(hosts)
	if err != nil {
		return nil, err
	}
	if ports.err != nil {
		return nil, ports.err
	}
	if len(ports.values) == 0 {
		return nil, fmt.Errorf("ports must not be empty")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, ErrShutdown
	}
	s.active.Add(1)
	s.mu.Unlock()
	scanCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.lifetime, cancel)
	results := make(chan Result, s.cfg.concurrency)
	go func() {
		defer s.active.Done()
		defer close(results)
		defer cancel()
		defer stop()
		s.run(scanCtx, normalized, ports.values, results)
	}()
	return results, nil
}

type job struct {
	host string
	ip   netip.Addr
	port uint16
}

func (s *Scanner) run(ctx context.Context, hosts []string, ports []uint16, results chan<- Result) {
	jobs := make(chan job)
	var workers sync.WaitGroup
	for i := 0; i < s.cfg.concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				if !s.acquire(ctx) {
					return
				}
				result := s.connect(ctx, j)
				s.release()
				if !emit(ctx, results, result) {
					return
				}
			}
		}()
	}
	func() {
		for _, host := range hosts {
			if ctx.Err() != nil {
				return
			}
			ips, duration, err := s.resolve(ctx, host)
			if err != nil {
				for _, port := range ports {
					if !emit(ctx, results, Result{Host: host, Port: port, State: classify(err), Duration: duration, Err: err}) {
						return
					}
				}
				continue
			}
			for _, ip := range ips {
				for _, port := range ports {
					if ctx.Err() != nil {
						return
					}
					select {
					case jobs <- job{host, ip, port}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	close(jobs)
	workers.Wait()
}

func (s *Scanner) acquire(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	select {
	case s.slots <- struct{}{}:
		if ctx.Err() != nil {
			s.release()
			return false
		}
		return true
	case <-ctx.Done():
		return false
	}
}
func (s *Scanner) release() { <-s.slots }

func (s *Scanner) resolve(ctx context.Context, host string) ([]netip.Addr, time.Duration, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, 0, nil
	}
	if !s.acquire(ctx) {
		return nil, 0, ctx.Err()
	}
	defer s.release()
	lookupCtx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()
	started := time.Now()
	ips, err := s.lookup(lookupCtx, host)
	duration := time.Since(started)
	if ctx.Err() != nil {
		err = context.Canceled
	}
	if err != nil {
		return nil, duration, fmt.Errorf("resolve %s: %w", host, err)
	}
	unique := make([]netip.Addr, 0, len(ips))
	seen := make(map[netip.Addr]bool)
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.IsValid() && !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	if len(unique) == 0 {
		return nil, duration, &net.DNSError{Name: host, Err: "no IP addresses", IsNotFound: true}
	}
	return unique, duration, nil
}

func (s *Scanner) connect(ctx context.Context, j job) Result {
	started := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.timeout)
	defer cancel()
	conn, err := s.dial(dialCtx, "tcp", net.JoinHostPort(j.ip.String(), strconv.Itoa(int(j.port))))
	if conn != nil {
		_ = conn.Close()
	}
	if ctx.Err() != nil {
		err = context.Canceled
	}
	return Result{Host: j.host, IP: j.ip, Port: j.port, State: classify(err), Duration: time.Since(started), Err: err}
}

func emit(ctx context.Context, out chan<- Result, result Result) bool {
	select {
	case out <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Scanner) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return fmt.Errorf("nil context")
	}
	s.mu.Lock()
	if !s.closing {
		s.closing = true
		go func() { s.active.Wait(); s.cancel(); close(s.done) }()
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	default:
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		s.cancel()
		return ctx.Err()
	}
}

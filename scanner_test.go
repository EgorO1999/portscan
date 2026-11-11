package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestCheckPortOpen(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	scanner, err := New(
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	result := scanner.checkPort(
		context.Background(),
		"127.0.0.1",
		net.ParseIP("127.0.0.1"),
		port,
	)

	if result.State != StateOpen {
		t.Fatalf("expected open, got %s: %v",
			result.State, result.Err)
	}
}

func TestScan(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	scanner, err := New(
		WithConcurrency(5),
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	results, err := scanner.Scan(
		context.Background(),
		[]string{"127.0.0.1", "127.0.0.1"},
		[]uint16{port, port},
	)
	if err != nil {
		t.Fatal(err)
	}

	count := 0

	for result := range results {
		count++

		if result.State != StateOpen {
			t.Errorf(
				"expected open, got %s: %v",
				result.State,
				result.Err,
			)
		}
	}

	if count != 1 {
		t.Errorf("expected 1 result, got %d", count)
	}
}

func TestResolveTargets(t *testing.T) {
	targets, err := resolveTargets(
		context.Background(),
		[]string{
			"127.0.0.1",
			"127.0.0.1",
			"::1",
			"localhost",
			"LOCALHOST",
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	if len(targets) < 3 {
		t.Fatalf("expected at least 3 targets, got %d", len(targets))
	}

	seen := make(map[string]struct{})

	for _, target := range targets {
		if target.ip == nil {
			t.Fatal("target IP must not be nil")
		}

		key := target.host + ":" + target.ip.String()

		if _, exists := seen[key]; exists {
			t.Fatalf("duplicate target: %s", key)
		}

		seen[key] = struct{}{}
	}
}

func TestResolveTargetsEmptyHost(t *testing.T) {
	_, err := resolveTargets(
		context.Background(),
		[]string{" "},
	)

	if err == nil {
		t.Fatal("expected error for empty host")
	}
}

func TestRange(t *testing.T) {
	got, err := Range(80, 85)
	if err != nil {
		t.Fatal(err)
	}

	want := []uint16{80, 81, 82, 83, 84, 85}

	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestRangeInvalid(t *testing.T) {
	tests := []struct {
		start int
		end   int
	}{
		{0, 100},
		{1000, 1},
		{80, 70000},
		{-1, 80},
	}

	for _, tt := range tests {
		_, err := Range(tt.start, tt.end)
		if err == nil {
			t.Errorf("expected error for range %d-%d", tt.start, tt.end)
		}
	}
}

func TestPortsInvalid(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		_, err := Ports(port)
		if err == nil {
			t.Errorf("expected error for port %d", port)
		}
	}

	if _, err := Ports(); err == nil {
		t.Fatal("expected error for empty ports")
	}
}

func TestUnion(t *testing.T) {
	first := []uint16{80, 443}
	second := []uint16{443, 444, 445}

	got := Union(first, second)
	want := []uint16{80, 443, 444, 445}

	if !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestScanCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{80, 443},
	)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}

	if results != nil {
		t.Fatal("expected nil results")
	}
}

func TestScanCancelClosesResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner, err := New(
		WithConcurrency(1),
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	ports, err := Range(1, 1000)
	if err != nil {
		t.Fatal(err)
	}

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		ports,
	)
	if err != nil {
		t.Fatal(err)
	}

	cancel()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	for {
		select {
		case _, ok := <-results:
			if !ok {
				return
			}

		case <-timer.C:
			t.Fatal("results channel was not closed after cancellation")
		}
	}
}

func TestScanSlowConsumer(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanner, err := New(
		WithConcurrency(1),
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{port},
	)
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan struct{})

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			conn.Close()
			close(accepted)
		}
	}()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("connection was not established")
	}

	cancel()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	for {
		select {
		case _, ok := <-results:
			if !ok {
				return
			}
		case <-timer.C:
			t.Fatal("scanner did not stop")
		}
	}
}

func TestScanConcurrentReuse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	scanner, err := New(
		WithConcurrency(5),
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			results, err := scanner.Scan(
				context.Background(),
				[]string{"127.0.0.1"},
				[]uint16{port},
			)
			if err != nil {
				t.Error(err)
				return
			}

			count := 0

			for result := range results {
				count++

				if result.State != StateOpen {
					t.Errorf("expected open, got %s", result.State)
				}
			}

			if count != 1 {
				t.Errorf("expected 1 result, got %d", count)
			}
		}()
	}

	wg.Wait()
}

func TestScanConcurrencyLimit(t *testing.T) {
	const limit = 3

	scanner, err := New(WithConcurrency(limit))
	if err != nil {
		t.Fatal(err)
	}

	var active atomic.Int32
	var peak atomic.Int32

	started := make(chan struct{}, 10)
	release := make(chan struct{})

	scanner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)

		for {
			old := peak.Load()

			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}

		started <- struct{}{}

		select {
		case <-release:
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ports, err := Range(10000, 10009)
	if err != nil {
		t.Fatal(err)
	}

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		ports,
	)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < limit; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatalf("workers did not start: %v", ctx.Err())
		}
	}

	select {
	case <-started:
		close(release)
		t.Fatal("concurrency limit exceeded")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	count := 0

	for result := range results {
		count++

		if result.State != StateClosed {
			t.Errorf("expected closed, got %s", result.State)
		}
	}

	if count != len(ports) {
		t.Fatalf("expected %d results, got %d", len(ports), count)
	}

	if got := peak.Load(); got != limit {
		t.Fatalf("expected peak concurrency %d, got %d", limit, got)
	}
}

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected State
	}{
		{
			name:     "open",
			err:      nil,
			expected: StateOpen,
		},
		{
			name:     "closed",
			err:      syscall.ECONNREFUSED,
			expected: StateClosed,
		},
		{
			name:     "timeout",
			err:      context.DeadlineExceeded,
			expected: StateTimeout,
		},
		{
			name:     "unreachable network",
			err:      syscall.ENETUNREACH,
			expected: StateUnreachable,
		},
		{
			name:     "unreachable host",
			err:      syscall.EHOSTUNREACH,
			expected: StateUnreachable,
		},
		{
			name:     "canceled",
			err:      context.Canceled,
			expected: StateCanceled,
		},
		{
			name:     "unknown error",
			err:      errors.New("unknown error"),
			expected: StateError,
		},
		{
			name:     "wrapped error",
			err:      fmt.Errorf("dial failed: %w", syscall.ECONNREFUSED),
			expected: StateClosed,
		},
		{
			name: "network timeout",
			err: &net.DNSError{
				IsTimeout: true,
			},
			expected: StateTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyError(tt.err)

			if got != tt.expected {
				t.Errorf(
					"expected %s, got %s",
					tt.expected,
					got,
				)
			}
		})
	}
}

func TestCheckPortErrorStates(t *testing.T) {
	tests := []struct {
		name  string
		err   error
		state State
	}{
		{"closed", syscall.ECONNREFUSED, StateClosed},
		{"timeout", context.DeadlineExceeded, StateTimeout},
		{"unreachable", syscall.ENETUNREACH, StateUnreachable},
		{"canceled", context.Canceled, StateCanceled},
		{"error", errors.New("unknown error"), StateError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New()
			if err != nil {
				t.Fatal(err)
			}

			scanner.dial = func(
				ctx context.Context,
				network, address string,
			) (net.Conn, error) {
				return nil, tt.err
			}

			ip := net.ParseIP("127.0.0.1")

			result := scanner.checkPort(
				context.Background(),
				"127.0.0.1",
				ip,
				8080,
			)

			if result.State != tt.state {
				t.Errorf("expected %s, got %s", tt.state, result.State)
			}

			if !errors.Is(result.Err, tt.err) {
				t.Errorf("expected error %v, got %v", tt.err, result.Err)
			}

			if result.Port != 8080 {
				t.Errorf("expected port 8080, got %d", result.Port)
			}

			if !result.IP.Equal(ip) {
				t.Errorf("expected IP %s, got %s", ip, result.IP)
			}

			if result.Host != "127.0.0.1" {
				t.Errorf("unexpected host: %s", result.Host)
			}
		})
	}
}

func TestCheckPortClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}

	scanner.dial = func(
		ctx context.Context,
		network, address string,
	) (net.Conn, error) {
		return client, nil
	}

	result := scanner.checkPort(
		context.Background(),
		"127.0.0.1",
		net.ParseIP("127.0.0.1"),
		8080,
	)

	if result.State != StateOpen {
		t.Fatalf("expected open, got %s", result.State)
	}

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	buf := make([]byte, 1)

	_, err = server.Read(buf)

	if !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF after connection close, got %v", err)
	}
}

func TestNewInvalidOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "zero concurrency",
			opts: []Option{WithConcurrency(0)},
		},
		{
			name: "negative concurrency",
			opts: []Option{WithConcurrency(-1)},
		},
		{
			name: "zero timeout",
			opts: []Option{WithConnectTimeout(0)},
		},
		{
			name: "negative timeout",
			opts: []Option{WithConnectTimeout(-time.Second)},
		},
		{
			name: "nil option",
			opts: []Option{nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New(tt.opts...)

			if err == nil {
				t.Fatal("expected error")
			}

			if scanner != nil {
				t.Fatal("expected nil scanner")
			}
		})
	}
}

func TestScanInvalidInput(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		ctx   context.Context
		hosts []string
		ports []uint16
	}{
		{
			name:  "nil context",
			ctx:   nil,
			hosts: []string{"127.0.0.1"},
			ports: []uint16{80},
		},
		{
			name:  "empty hosts",
			ctx:   context.Background(),
			hosts: []string{},
			ports: []uint16{80},
		},
		{
			name:  "empty ports",
			ctx:   context.Background(),
			hosts: []string{"127.0.0.1"},
			ports: []uint16{},
		},
		{
			name:  "empty host",
			ctx:   context.Background(),
			hosts: []string{""},
			ports: []uint16{80},
		},
		{
			name:  "zero port",
			ctx:   context.Background(),
			hosts: []string{"127.0.0.1"},
			ports: []uint16{0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := scanner.Scan(
				tt.ctx,
				tt.hosts,
				tt.ports,
			)

			if err == nil {
				t.Fatal("expected error")
			}

			if results != nil {
				t.Fatal("expected nil results")
			}
		})
	}
}

func TestScanSharedConcurrencyLimit(t *testing.T) {
	const limit = 2

	scanner, err := New(WithConcurrency(limit))
	if err != nil {
		t.Fatal(err)
	}

	var active atomic.Int32
	var peak atomic.Int32

	started := make(chan struct{}, 6)
	release := make(chan struct{})

	scanner.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		n := active.Add(1)
		defer active.Add(-1)

		for {
			old := peak.Load()

			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}

		started <- struct{}{}

		select {
		case <-release:
			return nil, syscall.ECONNREFUSED
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hosts := []string{"127.0.0.1"}
	ports := []uint16{10001, 10002, 10003}

	first, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	second, err := scanner.Scan(ctx, hosts, ports)
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < limit; i++ {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatalf("workers did not start: %v", ctx.Err())
		}
	}

	select {
	case <-started:
		t.Fatal("shared concurrency limit exceeded")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	count := 0

	for result := range first {
		count++

		if result.State != StateClosed {
			t.Errorf("expected closed, got %s", result.State)
		}
	}

	for result := range second {
		count++

		if result.State != StateClosed {
			t.Errorf("expected closed, got %s", result.State)
		}
	}

	if count != 6 {
		t.Fatalf("expected 6 results, got %d", count)
	}

	if got := peak.Load(); got != limit {
		t.Fatalf("expected peak concurrency %d, got %d", limit, got)
	}
}

func TestScanCancelDuringDial(t *testing.T) {
	scanner, err := New(WithConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})

	scanner.dial = func(
		ctx context.Context,
		network, address string,
	) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := scanner.Scan(
		ctx,
		[]string{"127.0.0.1"},
		[]uint16{8080},
	)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("dial did not start")
	}

	cancel()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	for {
		select {
		case _, ok := <-results:
			if !ok {
				return
			}
		case <-timer.C:
			t.Fatal("scanner did not stop after cancellation")
		}
	}
}

func TestScanUnresolvableHost(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatal(err)
	}

	called := false

	scanner.lookupIP = func(
		ctx context.Context,
		host string,
	) ([]net.IPAddr, error) {
		called = true

		return nil, &net.DNSError{
			Err:        "no such host",
			Name:       host,
			IsNotFound: true,
		}
	}

	results, err := scanner.Scan(
		context.Background(),
		[]string{"nonexistent-host.invalid"},
		[]uint16{80},
	)

	if !called {
		t.Fatal("DNS resolver was not called")
	}

	if err == nil {
		t.Fatal("expected DNS resolution error")
	}

	var dnsErr *net.DNSError

	if !errors.As(err, &dnsErr) {
		t.Fatalf("expected DNS error, got %T: %v", err, err)
	}

	if !dnsErr.IsNotFound {
		t.Fatalf("expected DNS not found error, got %v", err)
	}

	if results != nil {
		t.Fatal("expected nil results")
	}
}

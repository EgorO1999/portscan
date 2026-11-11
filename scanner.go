package portscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
	dial           func(context.Context, string, string) (net.Conn, error)
	lookupIP       func(context.Context, string) ([]net.IPAddr, error)
	slots          chan struct{}
}

func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    100,
		connectTimeout: 500 * time.Millisecond,
	}

	for _, opt := range opts {
		if opt == nil {
			return nil, fmt.Errorf("nil scanner option")
		}

		if err := opt(s); err != nil {
			return nil, err
		}
	}

	s.slots = make(chan struct{}, s.concurrency)

	s.dial = (&net.Dialer{
		Timeout: s.connectTimeout,
	}).DialContext

	s.lookupIP = net.DefaultResolver.LookupIPAddr

	return s, nil
}

func (s *Scanner) checkPort(
	ctx context.Context,
	host string,
	ip net.IP,
	port uint16,
) Result {

	start := time.Now()

	address := net.JoinHostPort(
		ip.String(),
		strconv.Itoa(int(port)),
	)

	conn, err := s.dial(ctx, "tcp", address)

	result := Result{
		Host:     host,
		IP:       ip,
		Port:     port,
		Duration: time.Since(start),
		Err:      err,
	}

	if err != nil {
		result.State = classifyError(err)
		return result
	}

	result.State = StateOpen
	conn.Close()

	return result
}

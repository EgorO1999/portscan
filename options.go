package portscan

import (
	"fmt"
	"time"
)

type Option func(*Scanner) error

func WithConcurrency(n int) Option {
	return func(s *Scanner) error {
		if n <= 0 {
			return fmt.Errorf("concurrency must be positive: %d", n)
		}

		s.concurrency = n
		return nil
	}
}

func WithConnectTimeout(timeout time.Duration) Option {
	return func(s *Scanner) error {
		if timeout <= 0 {
			return fmt.Errorf("connect timeout must be positive: %s", timeout)
		}

		s.connectTimeout = timeout
		return nil
	}
}

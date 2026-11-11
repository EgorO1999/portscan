package portscan

import (
	"context"
	"errors"
	"net"
	"syscall"
)

func classifyError(err error) State {
	if err == nil {
		return StateOpen
	}

	switch {
	case errors.Is(err, context.Canceled):
		return StateCanceled

	case errors.Is(err, context.DeadlineExceeded):
		return StateTimeout

	case errors.Is(err, syscall.ECONNREFUSED):
		return StateClosed

	case errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.EHOSTUNREACH):
		return StateUnreachable
	}

	var netErr net.Error

	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}

	return StateError
}

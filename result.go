package portscan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

type State string

const (
	Open        State = "open"
	Closed      State = "closed"
	Timeout     State = "timeout"
	Unreachable State = "unreachable"
	Canceled    State = "canceled"
	Error       State = "error"
)

type Result struct {
	Host     string
	IP       netip.Addr
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

func classify(err error) State {
	if err == nil {
		return Open
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return Closed
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETDOWN) || errors.Is(err, syscall.EHOSTDOWN) {
		return Unreachable
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	return Error
}

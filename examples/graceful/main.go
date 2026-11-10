// Command graceful demonstrates application-owned signal handling.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/portscan"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	scanner, err := portscan.New(portscan.WithConcurrency(16), portscan.WithConnectTimeout(500*time.Millisecond))
	if err != nil {
		return err
	}
	// A signal starts the grace period; it must not cancel the scan immediately.
	scanCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, err := scanner.Scan(scanCtx, []string{"127.0.0.1"}, portscan.Union(portscan.List(22, 80, 443), portscan.Range(8000, 8010)))
	if err != nil {
		return err
	}
	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		for result := range results {
			fmt.Printf("%s %s:%d %s (%s)\n", result.Host, result.IP, result.Port, result.State, result.Duration)
		}
	}()
	select {
	case <-signals.Done():
		stop()
	case <-consumed:
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	err = scanner.Shutdown(shutdownCtx)
	if err != nil {
		// Shutdown has requested cancellation. Wait for workers and channel cleanup.
		if cleanupErr := scanner.Shutdown(context.Background()); cleanupErr != nil {
			return cleanupErr
		}
	}
	<-consumed
	return err
}

package handshake

import (
	"context"
	"golang.org/x/sync/errgroup"
	"time"

	"git.samanthony.xyz/hose/util"
)

const (
	port    = "60322"
	network = "tcp"

	timeout       = 1 * time.Minute
	retryInterval = 500 * time.Millisecond
)

// Handshake exchanges public keys with a remote host.
// The user is asked to verify the received keys before they are saved in the known hosts file.
func Handshake(rhost string) error {
	util.Logf("initiating handshake with %s...", rhost)

	errs := make(chan error, 2)
	defer close(errs)

	group, ctx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		if err := send(rhost); err != nil {
			errs <- err
		}
		return nil
	})
	group.Go(func() error {
		if err := receive(rhost); err != nil {
			errs <- err
		}
		return nil
	})
	go func() { group.Wait() }() // cancel the context.

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		return nil
	}
}

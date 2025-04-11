package main

import (
	"golang.org/x/sync/errgroup"
	"net"

	"git.samanthony.xyz/hose/key"
)

// handshake exchanges public keys with a remote host.
// The user is asked to verify the fingerprint of the received key
// before it is saved in the known hosts file.
func handshake(rhost string) error {
	logf("initiating handshake with %s...", rhost)
	var group errgroup.Group
	group.Go(func() error { return handshakeSend(rhost) })
	group.Go(func() error { return handshakeRecv(rhost) })
	return group.Wait()
}

// handshakeSend sends the local public key to a remote host.
func handshakeSend(rhost string) error {
	pubkey, err := key.LoadPublicKey()
	if err != nil {
		return err
	}

	raddr := net.JoinHostPort(rhost, port)
	logf("connecting to %s...", raddr)
	conn, err := net.Dial(network, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("connected to %s", raddr)

	if _, err := conn.Write(pubkey[:]); err != nil {
		return err
	}

	logf("sent public key to %s", rhost)
	return nil
}

// handshakeRecv receives the public key of a remote host.
// The user is asked to verify the fingerprint of the key before
// it is saved to the known hosts file.
func handshakeRecv(rhost string) error {
	// TODO
}

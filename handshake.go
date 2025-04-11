package main

import (
	"bufio"
	"context"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"git.samanthony.xyz/hose/hosts"
	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

const (
	timeout       = 1 * time.Minute
	retryInterval = 500 * time.Millisecond
)

// handshake exchanges public keys with a remote host.
// The user is asked to verify the received key
// before it is saved in the known hosts file.
func handshake(rhost string) error {
	util.Logf("initiating handshake with %s...", rhost)

	errs := make(chan error, 2)
	defer close(errs)

	group, ctx := errgroup.WithContext(context.Background())
	group.Go(func() error {
		if err := handshakeSend(rhost); err != nil {
			errs <- err
		}
		return nil
	})
	group.Go(func() error {
		if err := handshakeRecv(rhost); err != nil {
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

// handshakeSend sends the local public key to a remote host.
func handshakeSend(rhost string) error {
	util.Logf("loading public key...")
	pubkey, err := key.LoadPublicKey()
	if err != nil {
		return err
	}

	raddr := net.JoinHostPort(rhost, port)
	util.Logf("connecting to %s...", raddr)
	conn, err := dialWithTimeout(network, raddr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Logf("connected to %s", raddr)

	if _, err := conn.Write(pubkey[:]); err != nil {
		return err
	}

	util.Logf("sent public key to %s", rhost)
	return nil
}

func dialWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	for {
		select {
		case <-ctx.Done(): // timeout.
			return nil, fmt.Errorf("dial %s %s: connection refused", network, address)
		default:
		}
		conn, err := net.Dial(network, address)
		if err == nil {
			return conn, nil
		}
		time.Sleep(retryInterval)
	}
}

// handshakeRecv receives the public key of a remote host.
// The user is asked to verify the key before it is saved to the known hosts file.
func handshakeRecv(rhost string) error {
	// Listen for connection.
	laddr := net.JoinHostPort("", port)
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	util.Logf("listening on %s", laddr)

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Logf("accepted connection from %s", conn.RemoteAddr())

	// Receive public key from remote host.
	var rpubkey [32]byte
	_, err = io.ReadFull(conn, rpubkey[:])
	if err != nil {
		return err
	}
	util.Logf("received public key from %s", conn.RemoteAddr())

	// Ask user to verify the key.
	ok, err := verifyPublicKey(conn.RemoteAddr(), rpubkey)
	if err != nil {
		return err
	}
	if !ok {
		// User rejected the key.
		return fmt.Errorf("host key verification failed")
	}

	return hosts.Set(conn.RemoteAddr(), rpubkey)
}

// verifyPublicKey asks the user to verify the public key of a remote host.
// It returns true if the user accepts the key, or false if they don't, or a non-nil error.
func verifyPublicKey(addr net.Addr, pubkey [32]byte) (bool, error) {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false, err
	}

	// Ask host to verify the key.
	util.Logf("Public key of host %q: %x\nIs this the correct key (yes/[no])?",
		host, pubkey[:])
	response, err := scan([]string{"yes", "no", ""})
	if err != nil {
		return false, err
	}
	switch response {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	case "":
		return false, nil // default option
	}
	panic("unreachable")
}

// scan reads from stdin until the user enters one of the valid responses.
func scan(responses []string) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	response := strings.TrimSpace(scanner.Text())
	for !slices.Contains(responses, response) {
		util.Logf("Please enter one of %q", responses)
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			return "", err
		}
		response = strings.TrimSpace(scanner.Text())
	}
	return response, nil
}

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

	"git.samanthony.xyz/hose/hosts"
	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

// handshake exchanges public keys with a remote host.
// The user is asked to verify the received key
// before it is saved in the known hosts file.
func handshake(rhost string) error {
	util.Logf("initiating handshake with %s...", rhost)
	group, _ := errgroup.WithContext(context.Background())
	group.Go(func() error { return handshakeSend(rhost) })
	group.Go(func() error { return handshakeRecv(rhost) })
	return group.Wait()
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
	conn, err := net.Dial(network, raddr)
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
	// Lookup human-friendly name of remote host, or fall back to the address.
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false, err
	}
	hostname, err := lookupAddr(host)
	if err != nil {
		return false, err
	}

	// Ask host to verify the key.
	util.Logf("Public key of host %q: %x\nIs this the correct key (yes/[no])?",
		hostname, pubkey[:])
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

// lookupAddr attempts to resolve the host name of an IP address.
// If no names are mapped to the address, the address itself is returned.
func lookupAddr(addr string) (string, error) {
	hostNames, err := net.LookupAddr(addr)
	if err != nil {
		return "", err
	}
	if len(hostNames) > 0 {
		return hostNames[0], nil
	}
	return addr, nil
}

// scan reads from stdin until the user enters one of the valid responses.
func scan(responses []string) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	response := scanner.Text()
	for !slices.Contains(responses, response) {
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			return "", err
		}
		response = scanner.Text()
	}
	return response, nil
}

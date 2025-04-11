package main

import (
	"fmt"
	"golang.org/x/sync/errgroup"
	"io"
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
	// Listen for connection.
	laddr := net.JoinHostPort("", port)
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	logf("listening on %s", laddr)

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("accepted connection from %s", conn.RemoteAddr())

	// Receive public key from remote host.
	var rpubkey [32]byte
	_, err = io.ReadFull(conn, rpubkey[:])
	if err != nil {
		return err
	}
	logf("received public key from $s", conn.RemoteAddr())

	// Ask user to verify the fingerprint of the key.
	ok, err := verifyPublicKey(conn.RemoteAddr(), rpubkey)
	if err != nil {
		return err
	}
	if !ok {
		// User rejected the fingerprint.
		return fmt.Errorf("host key verification failed")
	}

	return addKnownHost(conn.RemoteAddr(), rpubkey)
}

// verifyPublicKey asks the user to verify the fingerprint of a public key belonging to a remote host.
// It returns true if the user accepts the fingerprint, or false if they don't, or a non-nil error.
func verifyPublicKey(addr net.Addr, pubkey [32]byte) (bool, error) {
	// Lookup human-friendly name of remote host, or fall back to the address.
	hostname, err := lookupAddr(addr.String())
	if err != nil {
		return false, err
	}

	// Ask host to verify fingerprint.
	logf("Fingerprint of host %q: %s\nIs this the correct fingerprint (yes/[no])?",
		hostname, fingerprint(pubkey[:]))
	var response string
	n, err := fmt.Scanln(&response)
	if err != nil {
		return false, err
	}
	for n > 0 && response != "yes" && response != "no" {
		logf("Please type 'yes' or 'no'")
		n, err = fmt.Scanln(&response)
		if err != nil {
			return false, err
		}
	}
	if n == 0 {
		response = "no" // default response (pressed enter without typing anything)
	}
	switch response {
	case "yes":
		return true, nil
	case "no":
		return false, nil
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

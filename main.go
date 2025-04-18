package main

import (
	"flag"
	"fmt"
	"github.com/keybase/saltpack"
	"github.com/keybase/saltpack/basic"
	"github.com/tonistiigi/units"
	"io"
	"net"
	"net/netip"
	"os"

	"git.samanthony.xyz/hose/handshake"
	"git.samanthony.xyz/hose/hosts"
	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

const (
	port    = 60321
	network = "tcp"
	usage   = "Usage: hose <-handshake <rhost> | -r | -s <rhost>>"
)

var (
	handshakeHost = flag.String("handshake", "", "exchange public keys with remote host")
	recvFlag      = flag.Bool("r", false, "receive")
	sendHost      = flag.String("s", "", "send to remote host")
)

func main() {
	flag.Parse()
	if *handshakeHost != "" {
		if err := handshake.Handshake(*handshakeHost); err != nil {
			util.Eprintf("%v\n", err)
		}
	} else if *recvFlag {
		if err := recv(); err != nil {
			util.Eprintf("%v\n", err)
		}
	} else if *sendHost != "" {
		if err := send(*sendHost); err != nil {
			util.Eprintf("%v\n", err)
		}
	} else {
		util.Logf("%s", usage)
		flag.Usage()
		os.Exit(1)
	}
}

// recv pipes data from the remote host to stdout.
func recv() error {
	// Load private decryption key.
	keyring := key.NewKeyring()
	boxKeypair, err := key.LoadBoxKeypair()
	if err != nil {
		return err
	}
	keyring.ImportBoxKeypair(boxKeypair)

	// Accept connection from remote host.
	laddr := net.JoinHostPort("", fmt.Sprintf("%d", port))
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

	// Load remote host's signature verification key.
	rhost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	raddr, err := netip.ParseAddr(rhost)
	if err != nil {
		return err
	}
	host, err := hosts.Lookup(raddr)
	if err != nil {
		return err
	}
	keyring.ImportSigPublicKey(host.SigPublicKey)

	// Decrypt and verify stream.
	_, plaintext, err := saltpack.NewSigncryptOpenStream(conn, keyring, nil)
	if err != nil {
		return err
	}

	// Read data.
	n, err := io.Copy(os.Stdout, plaintext)
	util.Logf("received %.2f", units.Bytes(n)*units.B)
	return err
}

// send pipes data from stdin to the remote host.
func send(rHostName string) error {
	var keyCreator basic.EphemeralKeyCreator

	// Load sender signing keypair.
	util.Logf("loading signing key")
	sigKeypair, err := key.LoadSigKeypair()
	if err != nil {
		return err
	}

	// Create symmetric session key.
	sessionKey, err := key.NewReceiverSymmetricKey()
	if err != nil {
		return err
	}

	// Load receiver encryption key.
	util.Logf("loading encryption key for %s", rHostName)
	rAddr, err := netip.ParseAddr(rHostName)
	if err != nil {
		return err
	}
	rHost, err := hosts.Lookup(rAddr)
	if err != nil {
		return err
	}

	// Connect to remote host.
	rAddrPort := netip.AddrPortFrom(rAddr, port)
	util.Logf("connecting to %s", rAddrPort)
	conn, err := net.Dial(network, rAddrPort.String())
	if err != nil {
		return err
	}
	defer conn.Close()

	// Create signcrypted stream.
	util.Logf("signcrypting stream")
	rcvrBoxKeys := []saltpack.BoxPublicKey{rHost.BoxPublicKey}
	rcvrSymmetricKeys := []saltpack.ReceiverSymmetricKey{sessionKey}
	plaintext, err := saltpack.NewSigncryptSealStream(conn, keyCreator, sigKeypair, rcvrBoxKeys, rcvrSymmetricKeys)
	if err != nil {
		return err
	}
	defer plaintext.Close()

	// Send data.
	n, err := io.Copy(plaintext, os.Stdin)
	util.Logf("sent %.2f", units.Bytes(n)*units.B)
	return err
}

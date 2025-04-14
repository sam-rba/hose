package main

import (
	"flag"
	"github.com/tonistiigi/units"
	"io"
	"net"
	"os"

	"git.samanthony.xyz/hose/handshake"
	"git.samanthony.xyz/hose/util"
)

const (
	port    = "60321"
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

	n, err := io.Copy(os.Stdout, conn)
	util.Logf("received %.2f", units.Bytes(n)*units.B)
	return err
}

// send pipes data from stdin to the remote host.
func send(rhost string) error {
	raddr := net.JoinHostPort(rhost, port)
	util.Logf("connecting to %s...", raddr)
	conn, err := net.Dial(network, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Logf("connected to %s", raddr)

	n, err := io.Copy(conn, os.Stdin)
	util.Logf("sent %.2f", units.Bytes(n)*units.B)
	return err
}

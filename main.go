package main

import (
	"flag"
	"fmt"
	"github.com/tonistiigi/units"
	"io"
	"net"
	"os"
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
		if err := handshake(*handshakeHost); err != nil {
			eprintf("%v\n", err)
		}
	} else if *recvFlag {
		if err := recv(); err != nil {
			eprintf("%v\n", err)
		}
	} else if *sendHost != "" {
		if err := send(*sendHost); err != nil {
			eprintf("%v\n", err)
		}
	} else {
		logf("%s", usage)
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
	logf("listening on %s", laddr)

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("accepted connection from %s", conn.RemoteAddr())

	n, err := io.Copy(os.Stdout, conn)
	logf("received %.2f", units.Bytes(n)*units.B)
	return err
}

// send pipes data from stdin to the remote host.
func send(rhost string) error {
	raddr := net.JoinHostPort(rhost, port)
	logf("connecting to %s...", raddr)
	conn, err := net.Dial(network, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("connected to %s", raddr)

	n, err := io.Copy(conn, os.Stdin)
	logf("sent %.2f", units.Bytes(n)*units.B)
	return err
}

func eprintf(format string, a ...any) {
	logf(format, a...)
	os.Exit(1)
}

func logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "%s\n", msg)
}

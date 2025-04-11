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
	usage   = "Usage: hose <-r | -s <rhost>>"
)

var (
	r     = flag.Bool("r", false, "receive")
	rhost = flag.String("s", "", "send to remote host")
)

func main() {
	flag.Parse()
	if *r {
		if err := recv(); err != nil {
			eprintf("%v\n", err)
		}
	} else if *rhost != "" {
		if err := send(*rhost); err != nil {
			eprintf("%v\n", err)
		}
	} else {
		logf("%s\n", usage)
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
	logf("listening on %s\n", laddr)

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("accepted connection from %s\n", conn.RemoteAddr())

	n, err := io.Copy(os.Stdout, conn)
	logf("received %.2f\n", units.Bytes(n)*units.B)
	return err
}

// send pipes data from stdin to the remote host.
func send(rhost string) error {
	raddr := net.JoinHostPort(rhost, port)
	logf("connecting to %s...\n", raddr)
	conn, err := net.Dial(network, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	logf("connected to %s\n", raddr)

	n, err := io.Copy(conn, os.Stdin)
	logf("sent %.2f\n", units.Bytes(n)*units.B)
	return err
}

func eprintf(format string, a ...any) {
	logf(format, a...)
	os.Exit(1)
}

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
}

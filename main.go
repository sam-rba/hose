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
		fmt.Println(usage)
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
	fmt.Fprintf(os.Stderr, "listening on %s\n", laddr)

	conn, err := ln.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "accepted connection from %s\n", conn.RemoteAddr())

	n, err := io.Copy(os.Stdout, conn)
	fmt.Fprintf(os.Stderr, "received %.2f\n", units.Bytes(n)*units.B)
	return err
}

// send pipes data from stdin to the remote host.
func send(rhost string) error {
	raddr := net.JoinHostPort(rhost, port)
	fmt.Fprintf(os.Stderr, "connecting to %s...\n", raddr)
	conn, err := net.Dial(network, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "connected to %s\n", raddr)

	n, err := io.Copy(conn, os.Stdin)
	fmt.Fprintf(os.Stderr, "sent %.2f\n", units.Bytes(n)*units.B)
	return err
}

func eprintf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

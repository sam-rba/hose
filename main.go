package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const (
	port    = 60321
	timeout = time.Minute
	usage   = "Usage: hose <host>"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "%s\n", usage)
		os.Exit(1)
	}

	remote, err := parseHost(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve host '%s'\n", os.Args[1])
		os.Exit(1)
	} else if remote == nil {
		fmt.Fprintf(os.Stderr, "%s is not a valid IP address or host name\n",
			os.Args[1])
		os.Exit(1)
	}

	ifss, err := net.Interfaces()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	ifs := selectIfs(ifss)
	if ifs == nil {
		fmt.Fprintf(os.Stderr, "no suitable network interfaces\n")
		os.Exit(1)
	}
	local, err := ip(ifs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	} else if local == nil {
		fmt.Fprintf(os.Stderr, "no suitable ip addresses\n")
		os.Exit(1)
	}

	errs := make(chan error)
	go listen(local, remote, errs)
	go send(addr(remote, port), errs)
	// Wait for goroutines.
	nroutines := 2
	for i := 0; i < nroutines; i++ {
		if err := <-errs; err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}
}

// listen listens on local for connections from remote and copies received data
// to stdout. Sends exactly one (possible nil) error to errs.
func listen(local, remote net.IP, errs chan error) {
	l, err := net.Listen("tcp", addr(local, port))
	if err != nil {
		errs <- err
		return
	}

	var c net.Conn
	for {
		c, err = l.Accept()
		if err != nil {
			errs <- err
			return
		}
		host, _, err := net.SplitHostPort(c.RemoteAddr().String())
		if err != nil {
			errs <- err
			return
		}
		if host := net.ParseIP(host); host != nil && host.Equal(remote) {
			break
		}
	}

	io.Copy(os.Stdout, c)

	c.Close()
	l.Close()
	errs <- nil
}

// send sends data from stdin to addr. addr has the form "host:port" (see
// net.Dial). Sends exactly one (possible nil) error to errs.
func send(addr string, errs chan<- error) {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		errs <- err
		return
	}

	io.Copy(c, os.Stdin)

	c.Close()
	cancel()
	errs <- nil
}

// addr joins an IP address and a port number into a full address. See net.Dial.
func addr(ip net.IP, port uint) string {
	return net.JoinHostPort(fmt.Sprintf("%s", ip), fmt.Sprintf("%d", port))
}

// parseHost returns the IP address represented by s. s is either a literal IP
// address or a hostname. nil is returned if the hostname does not resolve to
// any addresses,
func parseHost(s string) (net.IP, error) {
	if ip := net.ParseIP(s); ip != nil {
		return ip, nil
	}
	addrs, err := net.LookupIP(s)
	if err != nil {
		return nil, err
	}
	if len(addrs) < 1 {
		return nil, nil
	}
	return addrs[0], nil
}

// selectIfs returns a network interface from ifs that is up, running and not
// a loopback interface. Returns nil if no such interface exists.
func selectIfs(ifs []net.Interface) *net.Interface {
	for _, i := range ifs {
		if (i.Flags&net.FlagUp != 0) &&
			(i.Flags&net.FlagRunning != 0) &&
			(i.Flags&net.FlagLoopback == 0) {
			return &i
		}
	}
	return nil
}

// ip returns the first IP address bound to ifs or nil if none are bound.
func ip(ifs *net.Interface) (net.IP, error) {
	addrs, err := ifs.Addrs()
	if err != nil {
		return nil, err
	} else if len(addrs) < 1 {
		return nil, nil
	}
	ip, _, err := net.ParseCIDR(addrs[0].String())
	if err != nil {
		return nil, err
	}
	return ip, nil
}

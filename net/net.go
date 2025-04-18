package net

import (
	"fmt"
	std_net "net"

	"git.samanthony.xyz/hose/util"
)

func AcceptConnection(network string, port uint16) (std_net.Conn, error) {
	laddr := std_net.JoinHostPort("", fmt.Sprintf("%d", port))
	ln, err := std_net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	util.Logf("listening on %s", laddr)
	return ln.Accept()
}

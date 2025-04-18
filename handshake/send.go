package handshake

import (
	"context"
	"fmt"
	"net"
	"time"

	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

// send sends the local public box (encryption) key to a remote host.
func send(rhost string) error {
	// Load keys from disc.
	boxPubKey, sigPubKey, err := loadKeys()
	if err != nil {
		return err
	}
	// Send them to the remote host.
	return sendKeys(rhost, boxPubKey, sigPubKey)
}

func loadKeys() (key.BoxPublicKey, key.SigPublicKey, error) {
	boxPubKey, err := key.LoadBoxPublicKey()
	if err != nil {
		return key.BoxPublicKey{}, key.SigPublicKey{}, err
	}
	sigPubKey, err := key.LoadSigPublicKey()
	return boxPubKey, sigPubKey, err
}

func sendKeys(rhost string, boxPubKey key.BoxPublicKey, sigPubKey key.SigPublicKey) error {
	raddr := net.JoinHostPort(rhost, fmt.Sprintf("%d", port))
	util.Logf("connecting to %s...", raddr)
	conn, err := dialWithTimeout(network, raddr, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Logf("connected to %s", raddr)

	if _, err := conn.Write(boxPubKey[:]); err != nil {
		return err
	}
	if _, err := conn.Write(sigPubKey[:]); err != nil {
		return err
	}
	util.Logf("sent public keys to %s", rhost)

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

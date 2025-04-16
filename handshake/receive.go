package handshake

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"

	"git.samanthony.xyz/hose/hosts"
	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

type keyType string

const (
	boxPublicKey keyType = "Public encryption key"
	sigPublicKey         = "Public signature verification key"
)

var errVerifyKey = errors.New("host key verification failed")

// receive receives the public keys of a remote host.
// The user is asked to verify the keys before they are saved to the known hosts file.
func receive(rhost string) error {
	conn, err := acceptConnection()
	if err != nil {
		return err
	}
	defer conn.Close()
	util.Logf("accepted connection from %s", conn.RemoteAddr())

	rBoxPubKey, rSigPubKey, err := receiveKeys(conn)
	if err != nil {
		return err
	}

	// Ask user to verify the keys.
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return err
	}
	raddr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}
	if err := verifyKeys(raddr, rBoxPubKey, rSigPubKey); err != nil {
		return err
	}

	// Save in known hosts file.
	return hosts.Add(hosts.Host{raddr, rBoxPubKey, rSigPubKey})
}

func acceptConnection() (net.Conn, error) {
	laddr := net.JoinHostPort("", port)
	ln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	util.Logf("listening on %s", laddr)
	return ln.Accept()
}

func receiveKeys(conn net.Conn) (key.BoxPublicKey, key.SigPublicKey, error) {
	// Receive public box (encryption) key from remote host.
	var rBoxPubKey key.BoxPublicKey
	_, err := io.ReadFull(conn, rBoxPubKey[:])
	if err != nil {
		return key.BoxPublicKey{}, key.SigPublicKey{}, err
	}
	util.Logf("received public encryption key from %s", conn.RemoteAddr())

	// Receive public signature verification key from remote host.
	var rSigPubKey key.SigPublicKey
	_, err = io.ReadFull(conn, rSigPubKey[:])
	if err != nil {
		return key.BoxPublicKey{}, key.SigPublicKey{}, err
	}
	util.Logf("receive public signature verification key from %s", conn.RemoteAddr())

	return rBoxPubKey, rSigPubKey, nil
}

// verifyKeys asks the user to verify keys received from a remote host.
// It returns a non-nil error if the user rejects the keys.
func verifyKeys(host netip.Addr, rBoxPubKey key.BoxPublicKey, rSigPubKey key.SigPublicKey) error {
	// Verify box key.
	if err := verifyKey(host, rBoxPubKey[:], boxPublicKey); err != nil {
		return err
	}
	// Verify signature verification key.
	return verifyKey(host, rSigPubKey[:], sigPublicKey)
}

// verifyKey asks the user to verify a key received from a remote host.
// It returns a non-nil error if the user rejects the key.
func verifyKey(host netip.Addr, key []byte, kt keyType) error {
	// Ask host to verify the key.
	util.Logf("%s key of host %q: %x\nIs this the correct key (yes/[no])?",
		kt, host, key[:])
	response, err := scan([]string{"yes", "no", ""})
	if err != nil {
		return err
	}
	switch response {
	case "yes":
		return nil
	case "no":
		return errVerifyKey
	case "":
		return errVerifyKey // default option
	}
	panic("unreachable")
}

// scan reads from stdin until the user enters one of the valid responses.
func scan(responses []string) (string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return "", err
	}
	response := strings.TrimSpace(scanner.Text())
	for !slices.Contains(responses, response) {
		util.Logf("Please enter one of %q", responses)
		scanner.Scan()
		if err := scanner.Err(); err != nil {
			return "", err
		}
		response = strings.TrimSpace(scanner.Text())
	}
	return response, nil
}

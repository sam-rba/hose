package hosts

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

var knownHostsFile = filepath.Join(xdg.DataHome, "hose", "known_hosts")

// Set sets the public key of a remote host.
// It replaces or creates an entry in the known hosts file.
func Set(hostport net.Addr, pubkey [32]byte) error {
	host, _, err := net.SplitHostPort(hostport.String())
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return err
	}

	hosts, err := Load()
	if err != nil {
		return err
	}

	hosts[addr] = pubkey

	return Store(hosts)
}

// Load loads the set of known hosts and their associated public keys
// from disc.
func Load() (map[netip.Addr][32]byte, error) {
	hosts := make(map[netip.Addr][32]byte)

	f, err := os.Open(knownHostsFile)
	if errors.Is(err, os.ErrNotExist) {
		return hosts, nil // no known hosts yet.
	} else if err != nil {
		return hosts, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		host, pubkey, err := parseHostKeyPair(scanner.Text())
		if err != nil {
			return hosts, fmt.Errorf("error parsing known hosts file: %s:%d: %v", err)
		}
		if _, ok := hosts[host]; ok {
			return hosts, fmt.Errorf("duplicate entry in known hosts file: %s", host)
		}
		hosts[host] = pubkey
	}
	return hosts, scanner.Err()
}

// parseHostKeyPair parses a line of the known hosts file.
func parseHostKeyPair(s string) (netip.Addr, [32]byte, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return netip.Addr{}, [32]byte{}, fmt.Errorf("expected 2 fields; got %d", len(fields))
	}

	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return netip.Addr{}, [32]byte{}, err
	}

	var key [32]byte
	if hex.DecodedLen(len(fields[1])) != len(key) {
		return netip.Addr{}, [32]byte{}, fmt.Errorf("malformed key: %s", fields[1])
	}
	if _, err := hex.Decode(key[:], []byte(fields[1])); err != nil {
		return netip.Addr{}, [32]byte{}, err
	}

	return addr, key, nil
}

// Store stores the set of known hosts and their associated public keys
// to disc. It overwrites the entire file.
func Store(hosts map[netip.Addr][32]byte) error {
	f, err := os.Create(knownHostsFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for host, key := range hosts {
		fmt.Fprintf(f, "%s %x", host, key)
	}

	return nil
}

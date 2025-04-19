package hosts

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"git.samanthony.xyz/hose/key"
	"git.samanthony.xyz/hose/util"
)

var knownHostsFile = filepath.Join(xdg.DataHome, "hose", "known_hosts")

type Host struct {
	netip.Addr       // address.
	key.BoxPublicKey // public encryption key.
	key.SigPublicKey // public signature verification key.
}

// Add adds or replaces an entry in the known hosts file.
func Add(host Host) error {
	hosts, err := Load()
	if err != nil {
		return err
	}

	i, ok := slices.BinarySearchFunc(hosts, host, cmpHost)
	if ok {
		util.Logf("replacing host %q in known hosts file", host.Addr)
		hosts[i] = host
	} else {
		hosts = slices.Insert(hosts, i, host)
	}

	return Store(hosts)
}

// Lookup searches for a host in the known hosts file.
// If it is not found, a non-nil error is returned.
func Lookup(hostname netip.Addr) (Host, error) {
	hosts, err := Load()
	if err != nil {
		return Host{}, err
	}
	i, ok := slices.BinarySearchFunc(hosts, hostname, cmpHostAddr)
	if ok {
		return hosts[i], nil
	}
	return Host{}, fmt.Errorf("no such host: %s", hostname)
}

// Load loads the set of known hosts from disc.
// The returned list is sorted.
func Load() ([]Host, error) {
	hosts := make([]Host, 0)

	f, err := os.Open(knownHostsFile)
	if errors.Is(err, os.ErrNotExist) {
		return hosts, nil // no known hosts yet.
	} else if err != nil {
		return hosts, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		host, err := parseHost(scanner.Bytes())
		if err != nil {
			return hosts, fmt.Errorf("error parsing known hosts file: %s:%d: %v", knownHostsFile, line, err)
		}
		i, ok := slices.BinarySearchFunc(hosts, host, cmpHost)
		if ok {
			return hosts, fmt.Errorf("duplicate entry in known hosts file: %s", host)
		}
		hosts = slices.Insert(hosts, i, host)
	}
	return hosts, scanner.Err()
}

// parseHost parses a line of the known hosts file.
func parseHost(b []byte) (Host, error) {
	fields := bytes.Fields(b)
	if len(fields) != 3 {
		return Host{}, fmt.Errorf("expected 3 fields; got %d", len(fields))
	}

	addr, err := netip.ParseAddr(string(fields[0]))
	if err != nil {
		return Host{}, err
	}

	boxPubKey, err := key.DecodeBoxPublicKey(fields[1])
	if err != nil {
		return Host{}, err
	}

	sigPubKey, err := key.DecodeSigPublicKey(fields[2])
	if err != nil {
		return Host{}, err
	}

	return Host{addr, boxPubKey, sigPubKey}, nil
}

// Store stores the set of known hosts to disc. It overwrites the entire file.
func Store(hosts []Host) error {
	slices.SortFunc(hosts, cmpHost)

	f, err := os.Create(knownHostsFile)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, host := range hosts {
		fmt.Fprintf(f, "%s\n", host)
	}

	return nil
}

func cmpHost(a, b Host) int {
	if x := a.Addr.Compare(b.Addr); x != 0 {
		return x
	}
	if x := a.BoxPublicKey.Compare(b.BoxPublicKey); x != 0 {
		return x
	}
	return a.SigPublicKey.Compare(b.SigPublicKey)
}

func cmpHostAddr(host Host, addr netip.Addr) int {
	return host.Addr.Compare(addr)
}

func (h Host) String() string {
	return fmt.Sprintf("%s %x %x", h.Addr, h.BoxPublicKey, h.SigPublicKey)
}

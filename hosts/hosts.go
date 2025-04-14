package hosts

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/adrg/xdg"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

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
		util.Logf("replacing host %q in known hosts file")
		hosts[i] = host
	} else {
		hosts = slices.Insert(hosts, i, host)
	}

	return Store(hosts)
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
		host, err := parseHost(scanner.Text())
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
func parseHost(s string) (Host, error) {
	fields := strings.Fields(s)
	if len(fields) != 3 {
		return Host{}, fmt.Errorf("expected 3 fields; got %d", len(fields))
	}

	addr, err := netip.ParseAddr(fields[0])
	if err != nil {
		return Host{}, err
	}

	var boxPubKey key.BoxPublicKey
	if hex.DecodedLen(len(fields[1])) != len(boxPubKey) {
		return Host{}, fmt.Errorf("malformed box public key: %s", fields[1])
	}
	if _, err := hex.Decode(boxPubKey[:], []byte(fields[1])); err != nil {
		return Host{}, err
	}

	var sigPubKey key.SigPublicKey
	if hex.DecodedLen(len(fields[2])) != len(sigPubKey) {
		return Host{}, fmt.Errorf("malformed signature public key: %s", fields[2])
	}
	if _, err := hex.Decode(sigPubKey[:], []byte(fields[2])); err != nil {
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

func (h Host) String() string {
	return fmt.Sprintf("%s %x %x", h.Addr, h.BoxPublicKey, h.SigPublicKey)
}

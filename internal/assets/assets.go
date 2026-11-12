// Package assets holds the list of your own machines: a name and its addresses. With it, an event that names
// a host and an event that names its address are known to be about the same machine.
package assets

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	// Field is the asset that wrote the event. SourceField and DestField are the assets at the two ends of a connection.
	Field       = "asset"
	SourceField = "src_asset"
	DestField   = "dst_asset"

	maxFileBytes = 1 << 20
	maxAssets    = 10_000
	maxAddresses = 64
)

var (
	ErrInvalid = errors.New("the asset list is not valid")
	validName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

type List struct {
	names     map[string]string
	addresses map[netip.Addr]string
	count     int
}

type document struct {
	Assets []struct {
		Name      string   `yaml:"name"`
		Addresses []string `yaml:"addresses"`
	} `yaml:"assets"`
}

func Load(path string) (*List, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s cannot be read", ErrInvalid, filepath.Base(path))
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		return nil, fmt.Errorf("%w: %s cannot be read or is too big", ErrInvalid, filepath.Base(path))
	}

	return Parse(data)
}

// Parse refuses a list in which a name or an address stands twice: one address must mean one machine.
func Parse(data []byte) (*List, error) {
	var parsed document
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: it must be YAML with a list \"assets\" of name and addresses", ErrInvalid)
	}
	if len(parsed.Assets) == 0 || len(parsed.Assets) > maxAssets {
		return nil, fmt.Errorf("%w: it has no asset, or too many", ErrInvalid)
	}

	list := &List{names: map[string]string{}, addresses: map[netip.Addr]string{}, count: len(parsed.Assets)}
	for _, asset := range parsed.Assets {
		if !validName.MatchString(asset.Name) {
			return nil, fmt.Errorf("%w: an asset has no usable name", ErrInvalid)
		}
		key := strings.ToLower(asset.Name)
		if _, taken := list.names[key]; taken {
			return nil, fmt.Errorf("%w: the name %s stands twice", ErrInvalid, asset.Name)
		}
		list.names[key] = asset.Name
		if len(asset.Addresses) > maxAddresses {
			return nil, fmt.Errorf("%w: %s has too many addresses", ErrInvalid, asset.Name)
		}
		for _, text := range asset.Addresses {
			address, err := netip.ParseAddr(text)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("%w: %s has an address that is not an address", ErrInvalid, asset.Name)
			}
			address = address.Unmap()
			if other, taken := list.addresses[address]; taken {
				return nil, fmt.Errorf("%w: the address %s belongs to %s and to %s", ErrInvalid, address, other, asset.Name)
			}
			list.addresses[address] = asset.Name
		}
	}

	return list, nil
}

func (list *List) Len() int {
	if list == nil {
		return 0
	}

	return list.count
}

func (list *List) byHost(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if name, found := list.names[host]; found {
		return name
	}
	if short, _, qualified := strings.Cut(host, "."); qualified {
		return list.names[short]
	}

	return ""
}

func (list *List) byAddress(text string) string {
	address, err := netip.ParseAddr(text)
	if err != nil {
		return ""
	}

	return list.addresses[address.Unmap()]
}

// Enrich sets the three asset fields of every event. A value that a log line brought under one of these
// names is removed first: only the list may say which machine an event is about.
func (list *List) Enrich(events []event.Event) {
	if list == nil {
		return
	}
	for _, current := range events {
		if current.Fields == nil {
			continue
		}
		delete(current.Fields, Field)
		delete(current.Fields, SourceField)
		delete(current.Fields, DestField)
		for field, name := range map[string]string{
			Field: list.byHost(current.Fields[event.Host]), SourceField: list.byAddress(current.Fields[event.SourceIP]), DestField: list.byAddress(current.Fields[event.DestIP]),
		} {
			if name != "" {
				current.Fields[field] = name
			}
		}
	}
}

// Package indicators holds a list of things that are known to be bad: addresses, domains and file hashes
// (indicators of compromise). An event that names one of them is marked, whatever kind of log it came from.
package indicators

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
	// Field is the indicator that an event names. TypeField is its kind, and WhereField is the field of the
	// event in which it was found.
	Field      = "indicator"
	TypeField  = "indicator_type"
	WhereField = "indicator_where"

	TypeIP     = "ip"
	TypeDomain = "domain"
	TypeSHA256 = "sha256"

	maxFileBytes  = 8 << 20
	maxIndicators = 200_000
	maxTextRunes  = 4096
)

var (
	ErrInvalid = errors.New("the indicator list is not valid")

	domainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
	hashPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	addressInText = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	nameInText    = regexp.MustCompile(`[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+`)

	// Where each kind is looked for. Text fields are searched for addresses and names inside them.
	addressFields = []string{event.SourceIP, event.DestIP}
	nameFields    = []string{"dns_query", "http_host", "tls_sni"}
	textFields    = []string{event.URL, event.Command, event.Referrer}
	hashFields    = []string{"sha256", "hash", "file_hash"}
)

type List struct {
	addresses map[netip.Addr]bool
	domains   map[string]bool
	hashes    map[string]bool
	count     int
}

type document struct {
	Indicators []struct {
		Type  string `yaml:"type"`
		Value string `yaml:"value"`
		Note  string `yaml:"note"`
	} `yaml:"indicators"`
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

// Parse refuses a list with an entry that it cannot use. An indicator that is silently dropped is a thing
// that the user believes is watched for and is not.
func Parse(data []byte) (*List, error) {
	var parsed document
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: it must be YAML with a list \"indicators\" of type and value", ErrInvalid)
	}
	if len(parsed.Indicators) == 0 || len(parsed.Indicators) > maxIndicators {
		return nil, fmt.Errorf("%w: it has no indicator, or too many", ErrInvalid)
	}

	list := &List{addresses: map[netip.Addr]bool{}, domains: map[string]bool{}, hashes: map[string]bool{}}
	for number, entry := range parsed.Indicators {
		value := strings.ToLower(strings.TrimSpace(entry.Value))
		switch entry.Type {
		case TypeIP:
			address, err := netip.ParseAddr(value)
			if err != nil || address.Zone() != "" {
				return nil, fmt.Errorf("%w: entry %d is not an address", ErrInvalid, number+1)
			}
			list.addresses[address.Unmap()] = true
		case TypeDomain:
			value = strings.TrimSuffix(value, ".")
			if len(value) > 253 || !domainPattern.MatchString(value) {
				return nil, fmt.Errorf("%w: entry %d is not a domain name", ErrInvalid, number+1)
			}
			list.domains[value] = true
		case TypeSHA256:
			if !hashPattern.MatchString(value) {
				return nil, fmt.Errorf("%w: entry %d is not a SHA-256 hash", ErrInvalid, number+1)
			}
			list.hashes[value] = true
		default:
			return nil, fmt.Errorf("%w: entry %d has a type that is not ip, domain or sha256", ErrInvalid, number+1)
		}
	}
	list.count = len(list.addresses) + len(list.domains) + len(list.hashes)

	return list, nil
}

func (list *List) Len() int {
	if list == nil {
		return 0
	}

	return list.count
}

// HasHash says whether a SHA-256 hash (in small or capital letters) is on the list.
func (list *List) HasHash(hash string) bool {
	return list != nil && list.hashes[strings.ToLower(hash)]
}

func (list *List) address(text string) (string, bool) {
	address, err := netip.ParseAddr(text)
	if err != nil {
		return "", false
	}
	address = address.Unmap()

	return address.String(), list.addresses[address]
}

// domain says whether a name is a listed domain or lies under one. It gives the listed domain.
func (list *List) domain(name string) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		if list.domains[name] {
			return name, true
		}
		_, rest, found := strings.Cut(name, ".")
		if !found {
			return "", false
		}
		name = rest
	}
}

type match struct{ value, kind, where string }

// standsAlone says that the digits and dots from start to end are a whole address and not a part of a longer
// number: "1203.0.113.80" and "1.203.0.113.80" do not name 203.0.113.80.
func standsAlone(text string, start, end int) bool {
	digit := func(at int) bool { return at >= 0 && at < len(text) && text[at] >= '0' && text[at] <= '9' }
	if digit(start-1) || digit(end) {
		return false
	}
	if start >= 2 && text[start-1] == '.' && digit(start-2) {
		return false
	}

	return !(end+1 < len(text) && text[end] == '.' && digit(end+1))
}

func (list *List) find(fields map[string]string) (match, bool) {
	for _, field := range addressFields {
		if value, found := list.address(fields[field]); found {
			return match{value, TypeIP, field}, true
		}
	}
	for _, field := range nameFields {
		if value, found := list.domain(fields[field]); found {
			return match{value, TypeDomain, field}, true
		}
	}
	for _, field := range hashFields {
		if value := strings.ToLower(fields[field]); list.hashes[value] {
			return match{value, TypeSHA256, field}, true
		}
	}
	for _, field := range textFields {
		text := strings.ToLower(fields[field])
		if text == "" {
			continue
		}
		if runes := []rune(text); len(runes) > maxTextRunes {
			text = string(runes[:maxTextRunes])
		}
		for _, span := range addressInText.FindAllStringIndex(text, 64) {
			if !standsAlone(text, span[0], span[1]) {
				continue
			}
			if value, found := list.address(text[span[0]:span[1]]); found {
				return match{value, TypeIP, field}, true
			}
		}
		for _, candidate := range nameInText.FindAllString(text, 64) {
			if value, found := list.domain(candidate); found {
				return match{value, TypeDomain, field}, true
			}
		}
	}

	return match{}, false
}

// Enrich marks every event that names an indicator. A value that a log line brought under one of the three
// field names is removed first: only the list may say that something is known to be bad.
// An event that names several indicators is marked with the first one that is found.
func (list *List) Enrich(events []event.Event) {
	if list == nil {
		return
	}
	for _, current := range events {
		if current.Fields == nil {
			continue
		}
		delete(current.Fields, Field)
		delete(current.Fields, TypeField)
		delete(current.Fields, WhereField)
		if found, matched := list.find(current.Fields); matched {
			current.Fields[Field], current.Fields[TypeField], current.Fields[WhereField] = found.value, found.kind, found.where
		}
	}
}

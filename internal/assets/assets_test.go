package assets

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenzietann/omamori/internal/event"
)

const good = "assets:\n  - name: web01\n    addresses: [10.0.1.10, '2001:db8::10']\n  - name: App01\n    addresses: [10.0.2.20]\n  - name: nameonly\n"

func enriched(t *testing.T, fields map[string]string) map[string]string {
	t.Helper()
	list, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	list.Enrich([]event.Event{{Fields: fields}})

	return fields
}

func TestEnrich(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want map[string]string
	}{
		{"host by name", map[string]string{"host": "web01"}, map[string]string{Field: "web01"}},
		{"host without regard to case", map[string]string{"host": "WEB01"}, map[string]string{Field: "web01"}},
		{"host with its domain", map[string]string{"host": "app01.corp.example.test"}, map[string]string{Field: "App01"}},
		{"both ends of a connection", map[string]string{"src_ip": "10.0.1.10", "dst_ip": "10.0.2.20"}, map[string]string{SourceField: "web01", DestField: "App01"}},
		{"IPv6 and IPv4 written as IPv6", map[string]string{"src_ip": "2001:db8:0:0::10", "dst_ip": "::ffff:10.0.2.20"}, map[string]string{SourceField: "web01", DestField: "App01"}},
		{"the host that wrote it and the address it saw", map[string]string{"host": "app01", "src_ip": "10.0.1.10"}, map[string]string{Field: "App01", SourceField: "web01"}},
		{"unknown host and address", map[string]string{"host": "other", "src_ip": "203.0.113.9", "dst_ip": "not an address"}, map[string]string{}},
		{"a name that only starts like an asset", map[string]string{"host": "web011"}, map[string]string{}},
		{"an address is not looked up as a name", map[string]string{"host": "10.0.1.10"}, map[string]string{}},
		// A log line can carry any field. It must not be able to say which of your machines it is about.
		{"values from the log are removed", map[string]string{Field: "db01", SourceField: "web01", DestField: "x", "src_ip": "203.0.113.9"}, map[string]string{}},
		{"values from the log are replaced", map[string]string{Field: "db01", "host": "web01"}, map[string]string{Field: "web01"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := enriched(t, testCase.in)
			for _, field := range []string{Field, SourceField, DestField} {
				if got[field] != testCase.want[field] {
					t.Errorf("%s is %q, want %q", field, got[field], testCase.want[field])
				}
			}
		})
	}
}

func TestNoListChangesNothing(t *testing.T) {
	var list *List
	fields := map[string]string{"host": "web01", Field: "from the log"}
	list.Enrich([]event.Event{{Fields: fields}, {}})
	if fields[Field] != "from the log" || list.Len() != 0 {
		t.Fatal("a missing list changed an event")
	}
}

func TestListsThatMustBeRefused(t *testing.T) {
	cases := map[string]string{
		"not yaml":              "assets: [",
		"empty":                 "",
		"no assets":             "assets: []",
		"unknown key":           "assets:\n  - name: a\n    role: web\n",
		"no name":               "assets:\n  - addresses: [10.0.0.1]\n",
		"name with a space":     "assets:\n  - name: 'web 01'\n",
		"name with a control":   "assets:\n  - name: \"web\\u001b[2J\"\n",
		"name twice":            "assets:\n  - name: web01\n  - name: WEB01\n",
		"address twice":         "assets:\n  - name: a\n    addresses: [10.0.0.1]\n  - name: b\n    addresses: ['::ffff:10.0.0.1']\n",
		"address is a network":  "assets:\n  - name: a\n    addresses: [10.0.0.0/8]\n",
		"address is a name":     "assets:\n  - name: a\n    addresses: [example.test]\n",
		"address with a zone":   "assets:\n  - name: a\n    addresses: ['fe80::1%eth0']\n",
		"too many addresses":    "assets:\n  - name: a\n    addresses: [" + strings.Repeat("10.0.0.1, ", maxAddresses+1) + "]\n",
		"a list in place of it": "- name: a\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(text)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error is %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	folder := t.TempDir()
	path := filepath.Join(folder, "assets.yml")
	os.WriteFile(path, []byte(good), 0o600)
	list, err := Load(path)
	if err != nil || list.Len() != 3 {
		t.Fatalf("%d assets, %v", list.Len(), err)
	}
	big := filepath.Join(folder, "big.yml")
	os.WriteFile(big, []byte(good+"#"+strings.Repeat("x", maxFileBytes)), 0o600)
	for _, bad := range []string{filepath.Join(folder, "missing.yml"), folder, big} {
		if _, err := Load(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s gave %v", filepath.Base(bad), err)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(good)
	f.Add("assets:\n  - name: a\n    addresses: ['::1', 1.2.3.4]\n")
	f.Fuzz(func(t *testing.T, text string) {
		list, err := Parse([]byte(text))
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("unexpected kind of error: %v", err)
			}

			return
		}
		fields := map[string]string{"host": text, "src_ip": text, "dst_ip": "10.0.0.1"}
		list.Enrich([]event.Event{{Fields: fields}})
		for _, field := range []string{Field, SourceField, DestField} {
			if value, found := fields[field]; found && !validName.MatchString(value) {
				t.Fatalf("%s is %q, which is no name of the list", field, value)
			}
		}
	})
}

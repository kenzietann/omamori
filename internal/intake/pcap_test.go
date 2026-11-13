package intake

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/rules"
)

// capture writes a pcap file: a port scan of twenty-five ports that are refused, and one HTTP request of a
// scanner tool that is answered.
func capture() []byte {
	from, to := netip.MustParseAddr("203.0.113.77"), netip.MustParseAddr("10.0.1.10")
	start := time.Date(2026, 11, 13, 2, 49, 0, 0, time.UTC)
	var out bytes.Buffer
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(header[16:], 65535)
	binary.LittleEndian.PutUint32(header[20:], 1)
	out.Write(header)
	write := func(at time.Duration, source, dest netip.Addr, sourcePort, destPort uint16, flags byte, payload string) {
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp, sourcePort)
		binary.BigEndian.PutUint16(tcp[2:], destPort)
		tcp[12], tcp[13] = 5<<4, flags
		tcp = append(tcp, payload...)
		ip := make([]byte, 20)
		ip[0], ip[9] = 0x45, 6
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)))
		copy(ip[12:], source.AsSlice())
		copy(ip[16:], dest.AsSlice())
		frame := append(append(make([]byte, 12), 0x08, 0x00), append(ip, tcp...)...)
		when := start.Add(at)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record, uint32(when.Unix()))
		binary.LittleEndian.PutUint32(record[4:], uint32(when.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(record[8:], uint32(len(frame)))
		binary.LittleEndian.PutUint32(record[12:], uint32(len(frame)))
		out.Write(record)
		out.Write(frame)
	}
	for port := uint16(1); port <= 25; port++ {
		write(time.Duration(port)*time.Millisecond, from, to, 50000+port, port, 0x02, "")
		write(time.Duration(port)*time.Millisecond+1, to, from, port, 50000+port, 0x14, "")
	}
	write(time.Second, from, to, 41000, 80, 0x02, "")
	write(time.Second+1, to, from, 80, 41000, 0x12, "")
	write(time.Second+2, from, to, 41000, 80, 0x18, "GET /.env HTTP/1.1\r\nHost: web01\r\nUser-Agent: sqlmap/1.8.2#stable\r\n\r\n")
	write(time.Second+3, to, from, 80, 41000, 0x18, "HTTP/1.1 404 Not Found\r\n\r\n")

	return out.Bytes()
}

func TestACaptureInAFolderIsReadAndFoundByTheRules(t *testing.T) {
	folder := t.TempDir()
	// The name says nothing: the capture is known by its first bytes.
	if err := os.WriteFile(filepath.Join(folder, "sensor.bin"), capture(), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(folder, "auth.log"), []byte("Nov 13 02:49:00 web01 sshd[1]: Accepted publickey for deploy from 10.0.1.5 port 5 ssh2\n"), 0o600)
	result, err := Read([]string{folder}, Options{Year: 2026, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	formats := map[string]Stats{}
	for _, file := range result.Files {
		formats[file.Format] = file
	}
	if got := formats[FormatPCAP]; got.File != "sensor.bin" || got.Lines != 54 || got.Malformed != 0 || got.Events != 27 || len(got.Sources) != 1 || got.Sources[0] != "pcap" {
		t.Fatalf("pcap stats %+v", got)
	}
	set, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, alert := range set.Evaluate(result.Events).Alerts {
		found[alert.Rule.Name] = true
	}
	for _, want := range []string{"net_port_scan", "web_scanner_tool"} {
		if !found[want] {
			t.Errorf("%s did not fire on the capture: %v", want, found)
		}
	}
}

func TestTheFormatPCAPRefusesText(t *testing.T) {
	_, _, err := Parse(bytes.NewReader([]byte("Nov 13 02:49:00 web01 sshd[1]: hello\n")), "x", Options{Year: 2026, Location: time.UTC, Format: FormatPCAP})
	if err != ErrFormat {
		t.Fatalf("got %v", err)
	}
}

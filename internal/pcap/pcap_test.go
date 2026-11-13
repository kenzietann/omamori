package pcap

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

var start = time.Date(2026, 11, 13, 2, 49, 0, 0, time.UTC)

var (
	attacker = netip.MustParseAddr("203.0.113.77")
	server   = netip.MustParseAddr("10.0.1.10")
	resolver = netip.MustParseAddr("10.0.0.2")
)

type byteOrder interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

type frame struct {
	at   time.Duration
	data []byte
}

func ipv4(source, dest netip.Addr, protocol byte, payload []byte) []byte {
	header := make([]byte, 20)
	header[0], header[8], header[9] = 0x45, 64, protocol
	binary.BigEndian.PutUint16(header[2:], uint16(20+len(payload)))
	copy(header[12:], source.AsSlice())
	copy(header[16:], dest.AsSlice())

	return append(header, payload...)
}

func tcpSegment(sourcePort, destPort uint16, sequence uint32, flags byte, payload string) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header, sourcePort)
	binary.BigEndian.PutUint16(header[2:], destPort)
	binary.BigEndian.PutUint32(header[4:], sequence)
	header[12], header[13] = 5<<4, flags

	return append(header, payload...)
}

func udpDatagram(sourcePort, destPort uint16, payload []byte) []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header, sourcePort)
	binary.BigEndian.PutUint16(header[2:], destPort)
	binary.BigEndian.PutUint16(header[4:], uint16(8+len(payload)))

	return append(header, payload...)
}

func ethernet(ip []byte) []byte {
	header := make([]byte, 14)
	binary.BigEndian.PutUint16(header[12:], 0x0800)

	return append(header, ip...)
}

type flowSide struct {
	from, to netip.Addr
	fromPort uint16
	toPort   uint16
}

func (side flowSide) tcp(at time.Duration, sequence uint32, flags byte, payload string) frame {
	return frame{at, ethernet(ipv4(side.from, side.to, protoTCP, tcpSegment(side.fromPort, side.toPort, sequence, flags, payload)))}
}

func (side flowSide) back() flowSide {
	return flowSide{side.to, side.from, side.toPort, side.fromPort}
}

func writePCAP(order byteOrder, link uint32, frames []frame) []byte {
	var out bytes.Buffer
	header := make([]byte, 24)
	order.PutUint32(header, 0xa1b2c3d4)
	order.PutUint16(header[4:], 2)
	order.PutUint16(header[6:], 4)
	order.PutUint32(header[16:], 65535)
	order.PutUint32(header[20:], link)
	out.Write(header)
	for _, current := range frames {
		when := start.Add(current.at)
		record := make([]byte, 16)
		order.PutUint32(record, uint32(when.Unix()))
		order.PutUint32(record[4:], uint32(when.Nanosecond()/1000))
		order.PutUint32(record[8:], uint32(len(current.data)))
		order.PutUint32(record[12:], uint32(len(current.data)))
		out.Write(record)
		out.Write(current.data)
	}

	return out.Bytes()
}

func block(order byteOrder, kind uint32, body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	out := make([]byte, 8, 12+len(body))
	order.PutUint32(out, kind)
	order.PutUint32(out[4:], uint32(12+len(body)))
	out = append(out, body...)

	return order.AppendUint32(out, uint32(12+len(body)))
}

func sectionHeader(order byteOrder) []byte {
	body := order.AppendUint32(nil, 0x1a2b3c4d)
	body = order.AppendUint16(body, 1)
	body = order.AppendUint16(body, 0)
	body = order.AppendUint64(body, ^uint64(0))

	return block(order, 0x0a0d0d0a, body)
}

// interfaceBlock writes an interface with the if_tsresol option when resolution is not zero.
func interfaceBlock(order byteOrder, link uint16, resolution byte) []byte {
	body := order.AppendUint16(nil, link)
	body = order.AppendUint16(body, 0)
	body = order.AppendUint32(body, 65535)
	if resolution != 0 {
		body = order.AppendUint16(body, 9)
		body = order.AppendUint16(body, 1)
		body = append(body, resolution, 0, 0, 0)
		body = append(body, 0, 0, 0, 0)
	}

	return block(order, 1, body)
}

func packetBlock(order byteOrder, index uint32, stamp uint64, data []byte) []byte {
	body := order.AppendUint32(nil, index)
	body = order.AppendUint32(body, uint32(stamp>>32))
	body = order.AppendUint32(body, uint32(stamp))
	body = order.AppendUint32(body, uint32(len(data)))
	body = order.AppendUint32(body, uint32(len(data)))

	return block(order, 6, append(body, data...))
}

func read(t *testing.T, data []byte) ([]event.Event, Stats) {
	t.Helper()
	events, stats, err := Read(bytes.NewReader(data), "capture.pcap")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	return events, stats
}

func only(events []event.Event, service string) []event.Event {
	var found []event.Event
	for _, current := range events {
		if current.Fields[event.Service] == service {
			found = append(found, current)
		}
	}

	return found
}

var web = flowSide{attacker, server, 40000, 80}

func httpExchange() []frame {
	back := web.back()
	return []frame{
		web.tcp(0, 100, flagSYN, ""),
		back.tcp(time.Millisecond, 500, flagSYN|flagACK, ""),
		web.tcp(2*time.Millisecond, 101, flagACK, ""),
		web.tcp(3*time.Millisecond, 101, flagACK, "GET /uploads/x.php?c=id HTTP/1.1\r\nHost: web01\r\nUser-Agent: curl/8.14.1\r\nReferer: http://web01/\r\n\r\n"),
		// The same request again: a retransmission.
		web.tcp(4*time.Millisecond, 101, flagACK, "GET /uploads/x.php?c=id HTTP/1.1\r\nHost: web01\r\nUser-Agent: curl/8.14.1\r\n\r\n"),
		back.tcp(5*time.Millisecond, 501, flagACK, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nuid="),
		web.tcp(6*time.Millisecond, 200, flagFIN|flagACK, ""),
		back.tcp(7*time.Millisecond, 600, flagFIN|flagACK, ""),
	}
}

func TestAnHTTPConnection(t *testing.T) {
	events, stats := read(t, writePCAP(binary.LittleEndian, linkEthernet, httpExchange()))
	if stats.Packets != 8 || stats.Malformed != 0 || stats.Skipped != 0 {
		t.Fatalf("stats %+v", stats)
	}
	requests := only(events, "http")
	if len(requests) != 1 {
		t.Fatalf("%d requests, want 1 (a retransmission is not a new request)", len(requests))
	}
	request := requests[0].Fields
	want := map[string]string{
		event.Product: "pcap", event.Category: "webserver", event.Action: "http_request", event.Method: "GET", event.URL: "/uploads/x.php?c=id",
		"http_host": "web01", event.UserAgent: "curl/8.14.1", event.Referrer: "http://web01/", event.Status: "200",
		event.SourceIP: "203.0.113.77", event.DestIP: "10.0.1.10", event.DestPort: "80", event.Protocol: "tcp",
	}
	for field, value := range want {
		if request[field] != value {
			t.Errorf("%s = %q, want %q", field, request[field], value)
		}
	}
	if requests[0].Ref != "capture.pcap:4" || !requests[0].Time.Equal(start.Add(3*time.Millisecond)) {
		t.Errorf("ref %s, time %v", requests[0].Ref, requests[0].Time)
	}
	connections := only(events, "conn")
	if len(connections) != 1 {
		t.Fatalf("%d connections", len(connections))
	}
	connection := connections[0].Fields
	if connection["conn_state"] != "SF" || connection["app_protocol"] != "http" || connection["packets_sent"] != "5" || connection["packets_received"] != "3" ||
		connection["bytes_received"] != "42" || connection[event.Category] != "network" || connections[0].Ref != "capture.pcap:1" {
		t.Errorf("connection %v %s", connection, connections[0].Ref)
	}
}

func TestConnectionStates(t *testing.T) {
	side := func(port uint16) flowSide { return flowSide{attacker, server, port, 22} }
	frames := []frame{
		side(1).tcp(0, 1, flagSYN, ""),
		side(2).tcp(0, 1, flagSYN, ""), side(2).back().tcp(1, 1, flagRST|flagACK, ""),
		side(3).tcp(0, 1, flagSYN, ""), side(3).back().tcp(1, 1, flagSYN|flagACK, ""), side(3).tcp(2, 2, flagRST, ""),
		side(4).tcp(0, 1, flagSYN, ""), side(4).back().tcp(1, 1, flagSYN|flagACK, ""), side(4).back().tcp(2, 2, flagRST, ""),
		side(5).tcp(0, 1, flagSYN, ""), side(5).back().tcp(1, 1, flagSYN|flagACK, ""), side(5).tcp(2, 2, flagACK, "SSH-2.0-x\r\n"),
		side(6).tcp(0, 9, flagACK, "midstream"),
		// The capture starts with the answer: the server is still the one that was asked.
		side(7).back().tcp(0, 1, flagSYN|flagACK, ""), side(7).tcp(1, 2, flagACK, ""),
	}
	events, _ := read(t, writePCAP(binary.BigEndian, linkEthernet, frames))
	states := map[string]string{}
	for _, current := range only(events, "conn") {
		states[current.Fields[event.SourcePort]] = current.Fields["conn_state"]
		if current.Fields[event.DestPort] != "22" {
			t.Errorf("the originator of %s is wrong: %v", current.Ref, current.Fields)
		}
	}
	want := map[string]string{"1": "S0", "2": "REJ", "3": "RSTO", "4": "RSTR", "5": "S1", "6": "OTH", "7": "S1"}
	for port, state := range want {
		if states[port] != state {
			t.Errorf("port %s: %q, want %q", port, states[port], state)
		}
	}
}

func TestAPortUsedAgainIsANewConnection(t *testing.T) {
	frames := append(httpExchange(), web.tcp(time.Second, 1000, flagSYN, ""))
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	connections := only(events, "conn")
	if len(connections) != 2 || connections[1].Fields["conn_state"] != "S0" {
		t.Fatalf("got %d connections: %v", len(connections), connections)
	}
}

func dnsQuery(id uint16, response bool, rcode byte, name string, kind uint16) []byte {
	message := binary.BigEndian.AppendUint16(nil, id)
	flags := uint16(0x0100)
	if response {
		flags |= 0x8000 | uint16(rcode)
	}
	message = binary.BigEndian.AppendUint16(message, flags)
	message = append(message, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0)
	message = binary.BigEndian.AppendUint16(message, kind)

	return binary.BigEndian.AppendUint16(message, 1)
}

func TestDNSQueriesAndAnswers(t *testing.T) {
	ask := func(at time.Duration, id uint16, name string) frame {
		return frame{at, ethernet(ipv4(server, resolver, protoUDP, udpDatagram(5353+id, 53, dnsQuery(id, false, 0, name, 1))))}
	}
	answer := func(at time.Duration, id uint16, name string, rcode byte) frame {
		return frame{at, ethernet(ipv4(resolver, server, protoUDP, udpDatagram(53, 5353+id, dnsQuery(id, true, rcode, name, 1))))}
	}
	frames := []frame{ask(0, 1, "Pool.Example.Test"), answer(1, 1, "pool.example.test", 3), ask(2, 2, "web01.lab"), ask(3, 3, "quiet.example.test"), answer(4, 2, "web01.lab", 0)}
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	queries := only(events, "dns")
	if len(queries) != 3 {
		t.Fatalf("%d queries", len(queries))
	}
	got := map[string]string{}
	for _, current := range queries {
		got[current.Fields["dns_query"]] = current.Fields["dns_rcode"] + "/" + current.Fields["dns_type"]
	}
	if got["pool.example.test"] != "NXDOMAIN/A" || got["web01.lab"] != "NOERROR/A" || got["quiet.example.test"] != "/A" {
		t.Fatalf("got %v", got)
	}
	for _, current := range only(events, "conn") {
		if current.Fields["app_protocol"] != "dns" || current.Fields[event.Protocol] != "udp" {
			t.Errorf("connection %v", current.Fields)
		}
	}
}

func TestDNSNamesCannotLoop(t *testing.T) {
	loop := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}
	if _, ok := parseDNS(loop); ok {
		t.Fatal("a pointer to itself was read")
	}
	long := []byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for index := 0; index < 10; index++ {
		long = append(long, 63)
		long = append(long, bytes.Repeat([]byte("a"), 63)...)
	}
	long = append(long, 0, 0, 1, 0, 1)
	if _, ok := parseDNS(long); ok {
		t.Fatal("a name over 255 bytes was read")
	}
	pointer := append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0xc0, 18}, []byte{4, 'l', 'a', 'b', 's', 0, 0, 1, 0, 1}...)
	if message, ok := parseDNS(pointer); !ok || message.name != "www.labs" {
		t.Fatalf("a pointer forward: %+v %v", message, ok)
	}
}

func clientHello(name string) []byte {
	server := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(name)))...)
	server = append(server, name...)
	list := append(binary.BigEndian.AppendUint16(nil, uint16(len(server))), server...)
	extension := append([]byte{0, 0}, binary.BigEndian.AppendUint16(nil, uint16(len(list)))...)
	extension = append(extension, list...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, binary.BigEndian.AppendUint16(nil, uint16(len(extension)))...)
	body = append(body, extension...)
	handshake := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)

	return append([]byte{0x16, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
}

func TestTheNameOfATLSServer(t *testing.T) {
	tls := flowSide{server, attacker, 41000, 443}
	frames := []frame{tls.tcp(0, 1, flagSYN, ""), tls.back().tcp(1, 1, flagSYN|flagACK, ""), tls.tcp(2, 2, flagACK, string(clientHello("Pool.Example.Test")))}
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	connection := only(events, "conn")[0].Fields
	if connection["tls_sni"] != "pool.example.test" || connection["app_protocol"] != "tls" {
		t.Fatalf("got %v", connection)
	}
	if name, ok := serverName(clientHello("x")[:30]); ok {
		t.Fatalf("a cut hello gave %q", name)
	}
}

func TestPCAPNG(t *testing.T) {
	data := []byte(ethernet(ipv4(attacker, server, protoTCP, tcpSegment(1, 22, 1, flagSYN, ""))))
	for _, order := range []byteOrder{binary.LittleEndian, binary.BigEndian} {
		var capture []byte
		capture = append(capture, sectionHeader(order)...)
		capture = append(capture, interfaceBlock(order, linkEthernet, 0)...)
		capture = append(capture, interfaceBlock(order, linkEthernet, 9)...)
		capture = append(capture, interfaceBlock(order, linkEthernet, 0x80|20)...)
		capture = append(capture, packetBlock(order, 0, uint64(start.UnixMicro()), data)...)
		capture = append(capture, packetBlock(order, 1, uint64(start.Add(time.Second).UnixNano()), data)...)
		capture = append(capture, packetBlock(order, 2, uint64(start.Add(2*time.Second).Unix())<<20, data)...)
		capture = append(capture, packetBlock(order, 9, 0, data)...)
		capture = append(capture, block(order, 3, binary.LittleEndian.AppendUint32(nil, uint32(len(data))))...)
		capture = append(capture, block(order, 0xbad, []byte("a custom block"))...)
		// A second section has its own interfaces: index 1 is gone.
		capture = append(capture, sectionHeader(order)...)
		capture = append(capture, interfaceBlock(order, linkEthernet, 0)...)
		capture = append(capture, packetBlock(order, 1, 0, data)...)
		capture = append(capture, packetBlock(order, 0, uint64(start.Add(3*time.Second).UnixMicro()), data)...)

		events, stats := read(t, capture)
		if stats.Packets != 4 || stats.Malformed != 2 || stats.NoTime != 1 {
			t.Fatalf("%v: stats %+v", order, stats)
		}
		var times []time.Time
		for _, current := range events {
			times = append(times, current.Time)
		}
		want := []time.Time{start, start.Add(time.Second), start.Add(2 * time.Second), start.Add(3 * time.Second)}
		if len(events) != 1 || !events[0].Time.Equal(start) {
			t.Fatalf("%v: %d events at %v, want one connection that starts at %v", order, len(events), times, want[0])
		}
		if events[0].Fields["packets_sent"] != "4" {
			t.Errorf("%v: %v", order, events[0].Fields)
		}
	}
}

func TestPCAPNGTimesWithEveryResolution(t *testing.T) {
	when := start.Add(1500 * time.Millisecond)
	cases := []struct {
		resolution byte
		stamp      uint64
	}{{0, uint64(when.UnixMicro())}, {6, uint64(when.UnixMicro())}, {9, uint64(when.UnixNano())}, {3, uint64(when.UnixMilli())}, {0x80 | 10, uint64(when.Unix())<<10 | 512}}
	for _, current := range cases {
		order := binary.LittleEndian
		capture := append(sectionHeader(order), interfaceBlock(order, linkRaw, current.resolution)...)
		capture = append(capture, packetBlock(order, 0, current.stamp, ipv4(attacker, server, protoUDP, udpDatagram(1, 2, nil)))...)
		events, _ := read(t, capture)
		if len(events) != 1 || !events[0].Time.Equal(when) {
			t.Errorf("resolution %#x: %v", current.resolution, events)
		}
	}
}

func TestLinkTypesAndIPv6(t *testing.T) {
	ip := ipv4(attacker, server, protoTCP, tcpSegment(1, 22, 1, flagSYN, ""))
	sll := append(make([]byte, 14), 0x08, 0x00)
	sll2 := append([]byte{0x08, 0x00}, make([]byte, 18)...)
	vlan := append(make([]byte, 12), 0x81, 0x00, 0, 5, 0x08, 0x00)
	loop := []byte{2, 0, 0, 0}
	v6source, v6dest := netip.MustParseAddr("2001:db8::77"), netip.MustParseAddr("2001:db8::10")
	ipv6 := make([]byte, 40)
	segment := tcpSegment(1, 22, 1, flagSYN, "")
	hop := append([]byte{protoTCP, 0}, make([]byte, 6)...)
	ipv6[0], ipv6[6] = 0x60, 0
	binary.BigEndian.PutUint16(ipv6[4:], uint16(len(hop)+len(segment)))
	copy(ipv6[8:], v6source.AsSlice())
	copy(ipv6[24:], v6dest.AsSlice())
	ipv6 = append(append(ipv6, hop...), segment...)
	cases := []struct {
		link uint32
		data []byte
		src  string
	}{
		{linkSLL, append(sll, ip...), "203.0.113.77"}, {linkSLL2, append(sll2, ip...), "203.0.113.77"},
		{linkEthernet, append(vlan, ip...), "203.0.113.77"}, {linkNull, append(loop, ip...), "203.0.113.77"},
		{linkRaw, ipv6, "2001:db8::77"},
	}
	for _, current := range cases {
		events, stats := read(t, writePCAP(binary.LittleEndian, current.link, []frame{{0, current.data}}))
		if len(events) != 1 || events[0].Fields[event.SourceIP] != current.src || events[0].Fields["conn_state"] != "S0" {
			t.Errorf("link %d: %v %+v", current.link, events, stats)
		}
	}
}

func TestPacketsThatAreNotReadAreCounted(t *testing.T) {
	arp := append(make([]byte, 12), 0x08, 0x06, 1, 2, 3)
	icmp := ethernet(ipv4(attacker, server, 1, []byte{8, 0, 0, 0}))
	fragment := ipv4(attacker, server, protoTCP, []byte("rest of a packet"))
	binary.BigEndian.PutUint16(fragment[6:], 100)
	broken := ethernet([]byte{0x45, 0, 0})
	shortTCP := ethernet(ipv4(attacker, server, protoTCP, []byte{1, 2, 3}))
	frames := []frame{{0, arp}, {0, icmp}, {0, ethernet(fragment)}, {0, broken}, {0, shortTCP}, {0, []byte{1}}}
	events, stats := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	if len(events) != 0 || stats.Skipped != 3 || stats.Malformed != 3 {
		t.Fatalf("events %v, stats %+v", events, stats)
	}
}

func TestBrokenCaptures(t *testing.T) {
	whole := writePCAP(binary.LittleEndian, linkEthernet, httpExchange())
	if events, _ := read(t, whole[:len(whole)-10]); len(only(events, "http")) != 1 {
		t.Error("a capture cut in its last packet lost the packets before")
	}
	for name, data := range map[string][]byte{"text": []byte("Nov 13 web01 sshd: hello"), "empty": nil, "short header": whole[:10]} {
		if _, _, err := Read(bytes.NewReader(data), "x"); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	huge := append([]byte{}, whole[:24]...)
	huge = append(huge, make([]byte, 16)...)
	binary.LittleEndian.PutUint32(huge[24+8:], maxPacketBytes+1)
	if _, _, err := Read(bytes.NewReader(huge), "x"); !errors.Is(err, ErrFormat) {
		t.Errorf("a packet longer than the limit: %v", err)
	}
	if !Sniff(whole) || Sniff([]byte("GET /")) || !Sniff(sectionHeader(binary.BigEndian)) {
		t.Error("Sniff")
	}
}

func TestHostileTextStaysText(t *testing.T) {
	back := web.back()
	frames := []frame{
		web.tcp(0, 1, flagSYN, ""), back.tcp(1, 1, flagSYN|flagACK, ""),
		web.tcp(2, 2, flagACK, "GET /a\x1b[31m\x00b HTTP/1.1\r\nUser-Agent: x\x07y\xff\r\nHost: "+strings.Repeat("h", 5000)+"\r\n\r\n"),
	}
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	request := only(events, "http")[0].Fields
	for field, value := range request {
		if strings.ContainsFunc(value, func(character rune) bool { return character < 0x20 || character == 0x7f }) || len([]rune(value)) > maxTextRunes {
			t.Errorf("%s = %q", field, value)
		}
	}
	if request[event.UserAgent] != "x y" {
		t.Errorf("user agent %q", request[event.UserAgent])
	}
}

func FuzzRead(f *testing.F) {
	f.Add(writePCAP(binary.LittleEndian, linkEthernet, httpExchange()))
	f.Add(writePCAP(binary.BigEndian, linkSLL, nil))
	order := binary.LittleEndian
	ng := append(sectionHeader(order), interfaceBlock(order, linkEthernet, 9)...)
	f.Add(append(ng, packetBlock(order, 0, 1, ethernet(ipv4(server, resolver, protoUDP, udpDatagram(1, 53, dnsQuery(1, false, 0, "a.b", 1)))))...))
	f.Add(append(ng, packetBlock(order, 0, 1, ethernet(ipv4(server, attacker, protoTCP, tcpSegment(1, 443, 1, flagACK, string(clientHello("x.test"))))))...))
	f.Fuzz(func(t *testing.T, data []byte) {
		events, _, err := Read(bytes.NewReader(data), "fuzz.pcap")
		if err != nil {
			return
		}
		for _, current := range events {
			for field, value := range current.Fields {
				if len([]rune(value)) > maxTextRunes || strings.ContainsFunc(value, func(character rune) bool { return character < 0x20 }) {
					t.Fatalf("%s = %q", field, value)
				}
			}
		}
	})
}

// Ethernet pads a short frame to 60 bytes. The padding is not data of the connection.
func TestPaddingIsNotCountedAsData(t *testing.T) {
	syn := ethernet(ipv4(attacker, server, protoTCP, tcpSegment(1, 22, 1, flagSYN, "")))
	padded := append(syn, make([]byte, 60-len(syn))...)
	answer := ethernet(ipv4(server, attacker, protoTCP, tcpSegment(22, 1, 1, flagRST|flagACK, "")))
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, []frame{{0, padded}, {1, append(answer, make([]byte, 60-len(answer))...)}}))
	if len(events) != 1 || events[0].Fields["bytes_sent"] != "0" || events[0].Fields["bytes_received"] != "0" || events[0].Fields["conn_state"] != "REJ" {
		t.Fatalf("got %v", events)
	}
}

// Two requests in a row on one connection get their answers in the same order.
func TestPipelinedRequestsGetTheirOwnStatus(t *testing.T) {
	back := web.back()
	frames := []frame{
		web.tcp(0, 1, flagSYN, ""), back.tcp(1, 1, flagSYN|flagACK, ""),
		web.tcp(2, 2, flagACK, "GET /first HTTP/1.1\r\nHost: a\r\n\r\n"),
		web.tcp(3, 40, flagACK, "GET /second HTTP/1.1\r\nHost: a\r\n\r\n"),
		back.tcp(4, 2, flagACK, "HTTP/1.1 200 OK\r\n\r\n"),
		back.tcp(5, 30, flagACK, "HTTP/1.1 404 Not Found\r\n\r\n"),
	}
	events, _ := read(t, writePCAP(binary.LittleEndian, linkEthernet, frames))
	got := map[string]string{}
	for _, request := range only(events, "http") {
		got[request.Fields[event.URL]] = request.Fields[event.Status]
	}
	if got["/first"] != "200" || got["/second"] != "404" {
		t.Fatalf("got %v", got)
	}
}

func TestAServerNameLongerThanItsExtensionIsRefused(t *testing.T) {
	hello := clientHello("pool.example.test")
	// The length of the name is in the two bytes before it. A name that says it is longer than its
	// extension must not be read from the bytes that follow.
	index := bytes.Index(hello, []byte("pool.example.test"))
	binary.BigEndian.PutUint16(hello[index-2:], 40)
	hello = append(hello, bytes.Repeat([]byte("x"), 64)...)
	if name, ok := serverName(hello); ok {
		t.Fatalf("got %q", name)
	}
}

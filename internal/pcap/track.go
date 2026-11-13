package pcap

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kenzietann/omamori/internal/event"
)

type flowKey struct {
	protocol uint8
	low      netip.AddrPort
	high     netip.AddrPort
}

func keyOf(protocol uint8, one, two netip.AddrPort) flowKey {
	if one.Compare(two) > 0 {
		one, two = two, one
	}

	return flowKey{protocol, one, two}
}

type flow struct {
	protocol                  uint8
	orig, resp                netip.AddrPort
	first, last               time.Time
	number                    int
	synOrig, synAck           bool
	rstOrig, rstResp          bool
	finOrig, finResp          bool
	bytesOrig, bytesResp      int64
	packetsOrig, packetsResp  int
	app, sni                  string
	pending                   []map[string]string
	requests                  int
	requestSeen, responseSeen map[uint32]bool
	sawPayloadOrig            bool
}

func (current *flow) closed() bool {
	return current.rstOrig || current.rstResp || current.finOrig && current.finResp
}

type dnsKey struct {
	client, server netip.AddrPort
	id             uint16
}

type tracker struct {
	name    string
	flows   map[flowKey]*flow
	done    []*flow
	events  []event.Event
	pending map[dnsKey]map[string]string
}

func newTracker(name string) *tracker {
	return &tracker{name: name, flows: map[flowKey]*flow{}, pending: map[dnsKey]map[string]string{}}
}

func (state *tracker) packet(current packet, stats *Stats) error {
	if len(state.events) > maxEvents {
		return ErrTooBig
	}
	ip, ok := network(current.linkType, current.data)
	if !ok {
		stats.Malformed++
		return nil
	}
	if ip == nil {
		stats.Skipped++
		return nil
	}
	found, ok := decode(ip)
	switch {
	case !ok:
		stats.Malformed++
		return nil
	case found.laterFragment || found.protocol != protoTCP && found.protocol != protoUDP || !found.source.IsValid():
		stats.Skipped++
		return nil
	}

	key := keyOf(found.protocol, found.source, found.dest)
	connection := state.flows[key]
	newStart := found.protocol == protoTCP && found.flags&(flagSYN|flagACK) == flagSYN
	if connection != nil && newStart && connection.closed() {
		state.done = append(state.done, connection)
		connection = nil
	}
	if connection == nil {
		if len(state.flows)+len(state.done) >= maxFlows {
			return ErrTooBig
		}
		connection = &flow{protocol: found.protocol, orig: found.source, resp: found.dest, first: current.when, number: current.number}
		// A capture that starts with the answer to a SYN still knows who began the connection.
		if found.protocol == protoTCP && found.flags&(flagSYN|flagACK) == flagSYN|flagACK {
			connection.orig, connection.resp = found.dest, found.source
		}
		state.flows[key] = connection
	}
	if current.when.After(connection.last) {
		connection.last = current.when
	}

	fromOrig := found.source == connection.orig
	if fromOrig {
		connection.packetsOrig++
		connection.bytesOrig += int64(found.payloadLength)
	} else {
		connection.packetsResp++
		connection.bytesResp += int64(found.payloadLength)
	}
	if found.protocol == protoTCP {
		state.tcp(connection, found, fromOrig, current)
	} else {
		state.udp(connection, found, fromOrig, current)
	}

	return nil
}

func (state *tracker) tcp(connection *flow, found segment, fromOrig bool, current packet) {
	flags := found.flags
	switch {
	case fromOrig && flags&(flagSYN|flagACK) == flagSYN:
		connection.synOrig = true
	case !fromOrig && flags&(flagSYN|flagACK) == flagSYN|flagACK:
		connection.synAck = true
	}
	if flags&flagRST != 0 {
		if fromOrig {
			connection.rstOrig = true
		} else {
			connection.rstResp = true
		}
	}
	if flags&flagFIN != 0 {
		if fromOrig {
			connection.finOrig = true
		} else {
			connection.finResp = true
		}
	}
	if len(found.payload) == 0 {
		return
	}
	if fromOrig {
		if !connection.sawPayloadOrig {
			connection.sawPayloadOrig = true
			if name, ok := serverName(found.payload); ok {
				connection.app, connection.sni = "tls", name
			}
		}
		state.request(connection, found, current)
	} else {
		state.response(connection, found)
	}
}

var methods = []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}

// request reads an HTTP request that starts at the beginning of a segment. A retransmitted segment has the same
// sequence number and is not read twice.
func (state *tracker) request(connection *flow, found segment, current packet) {
	data := found.payload
	method, _, _ := bytes.Cut(data[:min(len(data), 16)], []byte(" "))
	known := false
	for _, candidate := range methods {
		if string(method) == candidate {
			known = true
		}
	}
	if !known || connection.requests >= maxHTTPPerFlow {
		return
	}
	if connection.requestSeen == nil {
		connection.requestSeen = map[uint32]bool{}
	}
	if connection.requestSeen[found.sequence] {
		return
	}
	connection.requestSeen[found.sequence] = true

	head, _, _ := bytes.Cut(data, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return
	}
	connection.requests++
	connection.app = "http"
	fields := state.base(connection, "webserver", "http")
	fields[event.Action], fields[event.Method], fields[event.URL] = "http_request", tidy(parts[0]), tidy(parts[1])
	for index, line := range lines[1:] {
		if index >= maxHeaderFields {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = tidy(strings.TrimSpace(value))
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			fields["http_host"] = value
		case "user-agent":
			fields[event.UserAgent] = value
		case "referer":
			fields[event.Referrer] = value
		}
	}
	state.add(current.when, current.number, fields)
	connection.pending = append(connection.pending, fields)
}

// response gives the status of an HTTP answer to the oldest request of the connection that has none.
func (state *tracker) response(connection *flow, found segment) {
	data := found.payload
	if len(connection.pending) == 0 || !bytes.HasPrefix(data, []byte("HTTP/1.")) || len(data) < 12 {
		return
	}
	if connection.responseSeen == nil {
		connection.responseSeen = map[uint32]bool{}
	}
	if connection.responseSeen[found.sequence] {
		return
	}
	connection.responseSeen[found.sequence] = true
	code, err := strconv.Atoi(string(data[9:12]))
	if err != nil || code < 100 || code > 599 {
		return
	}
	connection.pending[0][event.Status] = strconv.Itoa(code)
	connection.pending = connection.pending[1:]
}

func (state *tracker) udp(connection *flow, found segment, fromOrig bool, current packet) {
	if found.dest.Port() != 53 && found.source.Port() != 53 {
		return
	}
	query, ok := parseDNS(found.payload)
	if !ok {
		return
	}
	connection.app = "dns"
	if !query.response {
		key := dnsKey{found.source, found.dest, query.id}
		if _, waiting := state.pending[key]; waiting || len(state.pending) >= maxDNSPending {
			return
		}
		fields := state.base(connection, "network", "dns")
		fields[event.Action], fields["dns_query"], fields["dns_type"] = "dns_query", query.name, query.kind
		state.add(current.when, current.number, fields)
		state.pending[key] = fields
		return
	}
	key := dnsKey{found.dest, found.source, query.id}
	if fields, waiting := state.pending[key]; waiting {
		fields["dns_rcode"] = query.rcode
		delete(state.pending, key)
	}
}

func (state *tracker) base(connection *flow, category, service string) map[string]string {
	return map[string]string{
		event.Product: Product, event.Category: category, event.Service: service,
		event.SourceIP: connection.orig.Addr().Unmap().String(), event.DestIP: connection.resp.Addr().Unmap().String(),
		event.SourcePort: strconv.Itoa(int(connection.orig.Port())), event.DestPort: strconv.Itoa(int(connection.resp.Port())),
		event.Protocol: protocolName(connection.protocol),
	}
}

func (state *tracker) add(when time.Time, number int, fields map[string]string) {
	state.events = append(state.events, event.Event{Time: when, Source: Product, Ref: fmt.Sprintf("%s:%d", state.name, number), Fields: fields})
}

func protocolName(protocol uint8) string {
	if protocol == protoTCP {
		return "tcp"
	}

	return "udp"
}

// state gives the state of a connection with the names of Zeek.
func (current *flow) state() string {
	if current.protocol == protoUDP {
		if current.packetsResp > 0 {
			return "SF"
		}
		return "S0"
	}
	switch {
	case !current.synOrig && !current.synAck:
		return "OTH"
	case !current.synAck && current.rstResp:
		return "REJ"
	case !current.synAck:
		return "S0"
	case current.rstOrig:
		return "RSTO"
	case current.rstResp:
		return "RSTR"
	case current.finOrig || current.finResp:
		return "SF"
	}

	return "S1"
}

// finish makes one event for each connection, after the events of its requests and queries.
func (state *tracker) finish() []event.Event {
	all := append(state.done, make([]*flow, 0, len(state.flows))...)
	for _, connection := range state.flows {
		all = append(all, connection)
	}
	for _, connection := range all {
		fields := state.base(connection, "network", "conn")
		fields[event.Action], fields["conn_state"] = "network_connect", connection.state()
		fields["bytes_sent"], fields["bytes_received"] = strconv.FormatInt(connection.bytesOrig, 10), strconv.FormatInt(connection.bytesResp, 10)
		fields["packets_sent"], fields["packets_received"] = strconv.Itoa(connection.packetsOrig), strconv.Itoa(connection.packetsResp)
		if connection.app != "" {
			fields["app_protocol"] = connection.app
		}
		if connection.sni != "" {
			fields["tls_sni"] = connection.sni
		}
		state.add(connection.first, connection.number, fields)
	}
	event.Sort(state.events)

	return state.events
}

func tidy(text string) string {
	text = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character == utf8.RuneError {
			return ' '
		}
		return character
	}, strings.ToValidUTF8(text, " "))
	text = strings.TrimSpace(text)
	if utf8.RuneCountInString(text) > maxTextRunes {
		text = string([]rune(text)[:maxTextRunes])
	}

	return text
}

type dnsMessage struct {
	id       uint16
	response bool
	name     string
	kind     string
	rcode    string
}

var dnsTypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}
var dnsCodes = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"}

// parseDNS reads the header and the first question of a DNS message. Pointers in the name are followed at
// most ten times, and the name is at most 255 bytes, so a message cannot make the reader loop.
func parseDNS(data []byte) (dnsMessage, bool) {
	if len(data) < 12 {
		return dnsMessage{}, false
	}
	flags := binary.BigEndian.Uint16(data[2:])
	message := dnsMessage{id: binary.BigEndian.Uint16(data), response: flags&0x8000 != 0}
	if code := int(flags & 0x0f); code < len(dnsCodes) {
		message.rcode = dnsCodes[code]
	} else {
		message.rcode = "RCODE" + strconv.Itoa(code)
	}
	if binary.BigEndian.Uint16(data[4:]) == 0 {
		return dnsMessage{}, false
	}
	var labels []string
	position, end, jumps, length := 12, -1, 0, 0
	for {
		if position >= len(data) {
			return dnsMessage{}, false
		}
		size := int(data[position])
		switch {
		case size == 0:
			if end < 0 {
				end = position + 1
			}
		case size&0xc0 == 0xc0:
			if position+1 >= len(data) || jumps >= 10 {
				return dnsMessage{}, false
			}
			if end < 0 {
				end = position + 2
			}
			position = int(binary.BigEndian.Uint16(data[position:]) & 0x3fff)
			jumps++
			continue
		case size&0xc0 != 0 || position+1+size > len(data):
			return dnsMessage{}, false
		default:
			length += size + 1
			if length > 255 {
				return dnsMessage{}, false
			}
			labels = append(labels, string(data[position+1:position+1+size]))
			position += 1 + size
			continue
		}
		break
	}
	if end+4 > len(data) {
		return dnsMessage{}, false
	}
	kind := binary.BigEndian.Uint16(data[end:])
	message.kind = dnsTypes[kind]
	if message.kind == "" {
		message.kind = "TYPE" + strconv.Itoa(int(kind))
	}
	message.name = tidy(strings.ToLower(strings.Join(labels, ".")))
	if message.name == "" {
		message.name = "."
	}

	return message, true
}

// serverName reads the name of the server from the first message of a TLS connection (the ClientHello).
func serverName(data []byte) (string, bool) {
	if len(data) < 43 || data[0] != 0x16 || data[1] != 3 || data[5] != 1 {
		return "", false
	}
	position := 5 + 4 + 2 + 32
	skip := func(width int) bool {
		if position+width > len(data) {
			return false
		}
		size := 0
		for index := 0; index < width; index++ {
			size = size<<8 | int(data[position+index])
		}
		position += width + size

		return position <= len(data)
	}
	if !skip(1) || !skip(2) || !skip(1) || position+2 > len(data) {
		return "", false
	}
	end := position + 2 + int(binary.BigEndian.Uint16(data[position:]))
	position += 2
	end = min(end, len(data))
	for position+4 <= end {
		kind, size := binary.BigEndian.Uint16(data[position:]), int(binary.BigEndian.Uint16(data[position+2:]))
		position += 4
		if position+size > end {
			return "", false
		}
		if kind == 0 && size >= 5 && data[position+2] == 0 {
			length := int(binary.BigEndian.Uint16(data[position+3:]))
			if 5+length > size || length == 0 || length > 255 {
				return "", false
			}
			return tidy(strings.ToLower(string(data[position+5 : position+5+length]))), true
		}
		position += size
	}

	return "", false
}

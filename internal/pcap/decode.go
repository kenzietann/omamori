package pcap

import (
	"encoding/binary"
	"net/netip"
)

// Link types of the frames that are read.
const (
	linkNull     = 0
	linkEthernet = 1
	linkRaw      = 101
	linkRawOld   = 12
	linkRawOld2  = 14
	linkLoop     = 108
	linkSLL      = 113
	linkSLL2     = 276
	linkIPv4     = 228
	linkIPv6     = 229
)

const (
	protoTCP = 6
	protoUDP = 17
)

// segment is the part of a packet that the tracker needs.
type segment struct {
	protocol      uint8
	source, dest  netip.AddrPort
	flags         uint8
	sequence      uint32
	payload       []byte
	payloadLength int
	firstFragment bool
	laterFragment bool
}

const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// network finds the IP packet in a frame. It gives the bytes from the IP header on, or nil.
func network(linkType uint32, data []byte) ([]byte, bool) {
	switch linkType {
	case linkEthernet:
		if len(data) < 14 {
			return nil, false
		}
		kind, rest := binary.BigEndian.Uint16(data[12:]), data[14:]
		// Up to two VLAN tags.
		for tags := 0; (kind == 0x8100 || kind == 0x88a8) && tags < 2; tags++ {
			if len(rest) < 4 {
				return nil, false
			}
			kind, rest = binary.BigEndian.Uint16(rest[2:]), rest[4:]
		}
		if kind != 0x0800 && kind != 0x86dd {
			return nil, true
		}
		return rest, true
	case linkSLL:
		if len(data) < 16 {
			return nil, false
		}
		if kind := binary.BigEndian.Uint16(data[14:]); kind != 0x0800 && kind != 0x86dd {
			return nil, true
		}
		return data[16:], true
	case linkSLL2:
		if len(data) < 20 {
			return nil, false
		}
		if kind := binary.BigEndian.Uint16(data); kind != 0x0800 && kind != 0x86dd {
			return nil, true
		}
		return data[20:], true
	case linkNull, linkLoop:
		if len(data) < 4 {
			return nil, false
		}
		// The family is in the byte order of the machine that captured: 2 is IPv4, 24, 28 and 30 are IPv6.
		family := binary.LittleEndian.Uint32(data)
		if family > 0xffff {
			family = binary.BigEndian.Uint32(data)
		}
		if family != 2 && family != 24 && family != 28 && family != 30 {
			return nil, true
		}
		return data[4:], true
	case linkRaw, linkRawOld, linkRawOld2, linkIPv4, linkIPv6:
		return data, true
	}

	return nil, true
}

// decode reads an IP packet and its TCP or UDP header. ok is false for a packet whose headers are broken;
// a packet of another kind gives ok true and a segment with protocol 0.
func decode(data []byte) (segment, bool) {
	if len(data) < 1 {
		return segment{}, false
	}
	switch data[0] >> 4 {
	case 4:
		return decodeIPv4(data)
	case 6:
		return decodeIPv6(data)
	}

	return segment{}, false
}

func decodeIPv4(data []byte) (segment, bool) {
	if len(data) < 20 {
		return segment{}, false
	}
	headerLength := int(data[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(data[2:]))
	if headerLength < 20 || total < headerLength || len(data) < headerLength {
		return segment{}, false
	}
	// A capture can cut a packet (snap length) or pad a frame. The IP length is believed only downward.
	if total < len(data) {
		data = data[:total]
	}
	fragment := binary.BigEndian.Uint16(data[6:])
	offset, more := fragment&0x1fff, fragment&0x2000 != 0
	source := netip.AddrFrom4([4]byte(data[12:16]))
	dest := netip.AddrFrom4([4]byte(data[16:20]))
	current := segment{protocol: data[9]}
	if offset != 0 {
		current.laterFragment = true
		return current, true
	}
	current.firstFragment = more

	return transport(current, source, dest, data[headerLength:], total-headerLength)
}

func decodeIPv6(data []byte) (segment, bool) {
	if len(data) < 40 {
		return segment{}, false
	}
	length := int(binary.BigEndian.Uint16(data[4:]))
	next := data[6]
	source := netip.AddrFrom16([16]byte(data[8:24]))
	dest := netip.AddrFrom16([16]byte(data[24:40]))
	rest := data[40:]
	if length < len(rest) {
		rest = rest[:length]
	}
	current := segment{}
	// Extension headers: hop-by-hop, routing, destination options, fragment. At most eight of them.
headers:
	for count := 0; count < 8; count++ {
		switch next {
		case 0, 43, 60:
			if len(rest) < 8 {
				return segment{}, false
			}
			size := (int(rest[1]) + 1) * 8
			if len(rest) < size {
				return segment{}, false
			}
			next, rest = rest[0], rest[size:]
			length -= size
			continue
		case 44:
			if len(rest) < 8 {
				return segment{}, false
			}
			fragment := binary.BigEndian.Uint16(rest[2:])
			if fragment&0xfff8 != 0 {
				current.protocol, current.laterFragment = rest[0], true
				return current, true
			}
			current.firstFragment = fragment&1 != 0
			next, rest = rest[0], rest[8:]
			length -= 8
			continue
		}
		break headers
	}
	current.protocol = next

	return transport(current, source, dest, rest, length)
}

func transport(current segment, source, dest netip.Addr, data []byte, length int) (segment, bool) {
	switch current.protocol {
	case protoTCP:
		if len(data) < 20 {
			return segment{}, false
		}
		offset := int(data[12]>>4) * 4
		if offset < 20 || len(data) < offset {
			return segment{}, false
		}
		current.source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(data))
		current.dest = netip.AddrPortFrom(dest, binary.BigEndian.Uint16(data[2:]))
		current.sequence = binary.BigEndian.Uint32(data[4:])
		current.flags = data[13]
		current.payload = data[offset:]
		current.payloadLength = max(length-offset, len(current.payload))
	case protoUDP:
		if len(data) < 8 {
			return segment{}, false
		}
		current.source = netip.AddrPortFrom(source, binary.BigEndian.Uint16(data))
		current.dest = netip.AddrPortFrom(dest, binary.BigEndian.Uint16(data[2:]))
		current.payload = data[8:]
		udpLength := int(binary.BigEndian.Uint16(data[4:]))
		if udpLength >= 8 && udpLength-8 < len(current.payload) {
			current.payload = current.payload[:udpLength-8]
		}
		current.payloadLength = max(udpLength-8, len(current.payload))
	}

	return current, true
}

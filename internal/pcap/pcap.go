// Package pcap reads packet captures (the pcap format of tcpdump and the pcapng format of Wireshark) and makes
// events of them, in the way of Zeek: one event for each connection, each HTTP request and each DNS query.
// The same rules that read Zeek logs read these events.
//
// A capture is data from a network that someone else controls, so every length in it is checked before it is
// used. Nothing in a packet is run, and nothing is sent anywhere. Packets that cannot be read are counted.
package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/kenzietann/omamori/internal/event"
)

const (
	// Product is the product field of the events, so that a rule or a person can tell them from Zeek.
	Product = "pcap"

	maxPacketBytes  = 256 << 10
	maxBlockBytes   = 1 << 20
	maxPackets      = 5_000_000
	maxFlows        = 200_000
	maxInterfaces   = 64
	maxHTTPPerFlow  = 1000
	maxDNSPending   = 100_000
	maxTextRunes    = 2048
	maxHeaderFields = 100
	maxEvents       = 1_000_000
)

var (
	ErrFormat = errors.New("the file is not a pcap or pcapng capture")
	ErrTooBig = errors.New("the capture holds more packets or connections than one run can take")
)

// Stats say what was read. Malformed packets are packets whose headers could not be read; Skipped are packets of
// kinds that are not looked at (ARP, ICMP, other link types, fragments after the first).
type Stats struct {
	Packets   int
	Malformed int
	Skipped   int
	// NoTime are packets of the simple pcapng block, which has no time. They are counted and not used.
	NoTime int
}

// Sniff says whether the first bytes of a file are those of a capture.
func Sniff(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(head) {
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1, 0x0a0d0d0a:
		return true
	}

	return false
}

// packet is one frame as it was captured.
type packet struct {
	number   int
	when     time.Time
	linkType uint32
	data     []byte
}

// Read reads a whole capture and gives the events. name is used in the reference of each event.
func Read(reader io.Reader, name string) ([]event.Event, Stats, error) {
	buffered := bufio.NewReaderSize(reader, 256<<10)
	head, err := buffered.Peek(4)
	if err != nil || !Sniff(head) {
		return nil, Stats{}, ErrFormat
	}
	state := newTracker(name)
	var stats Stats
	each := func(current packet) error {
		stats.Packets++
		if stats.Packets > maxPackets {
			return ErrTooBig
		}

		return state.packet(current, &stats)
	}
	if binary.BigEndian.Uint32(head) == 0x0a0d0d0a {
		err = readPCAPNG(buffered, each, &stats)
	} else {
		err = readPCAP(buffered, each)
	}
	if err != nil {
		return nil, Stats{}, err
	}

	return state.finish(), stats, nil
}

func readFull(reader io.Reader, size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, err
	}

	return data, nil
}

// readPCAP reads the format of tcpdump: a header of 24 bytes, then records of 16 bytes and the frame.
func readPCAP(reader io.Reader, each func(packet) error) error {
	header, err := readFull(reader, 24)
	if err != nil {
		return ErrFormat
	}
	var order binary.ByteOrder = binary.LittleEndian
	nano := false
	switch binary.BigEndian.Uint32(header) {
	case 0xa1b2c3d4:
		order = binary.BigEndian
	case 0xa1b23c4d:
		order, nano = binary.BigEndian, true
	case 0x4d3cb2a1:
		nano = true
	}
	linkType := order.Uint32(header[20:]) & 0x0fffffff
	for number := 1; ; number++ {
		record, err := readFull(reader, 16)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// A capture that was cut in the middle of a record is read up to the cut.
			return nil
		}
		seconds, fraction := order.Uint32(record), order.Uint32(record[4:])
		length := order.Uint32(record[8:])
		if length > maxPacketBytes {
			return fmt.Errorf("%w: a packet record says it is %d bytes long", ErrFormat, length)
		}
		data, err := readFull(reader, int(length))
		if err != nil {
			return nil
		}
		nanos := int64(fraction) * 1000
		if nano {
			nanos = int64(fraction)
		}
		if nanos >= 1e9 {
			nanos = 0
		}
		if err := each(packet{number: number, when: time.Unix(int64(seconds), nanos).UTC(), linkType: linkType, data: data}); err != nil {
			return err
		}
	}
}

type pcapngInterface struct {
	linkType uint32
	// tick is the length of one tick of the time stamp, in nanoseconds.
	tick float64
}

// readPCAPNG reads the format of Wireshark: blocks of a type and a length. A file can hold several sections,
// each with its own byte order and its own interfaces.
func readPCAPNG(reader io.Reader, each func(packet) error, stats *Stats) error {
	var order binary.ByteOrder = binary.LittleEndian
	var interfaces []pcapngInterface
	section := false
	for number := 1; ; {
		head, err := readFull(reader, 8)
		if err != nil {
			if !section {
				return ErrFormat
			}
			return nil
		}
		if binary.BigEndian.Uint32(head) == 0x0a0d0d0a {
			// The section header says the byte order of everything after it, its own length included.
			magic, err := readFull(reader, 4)
			if err != nil {
				return ErrFormat
			}
			switch binary.BigEndian.Uint32(magic) {
			case 0x1a2b3c4d:
				order = binary.BigEndian
			case 0x4d3c2b1a:
				order = binary.LittleEndian
			default:
				return ErrFormat
			}
			length := order.Uint32(head[4:])
			if length < 28 || length%4 != 0 || length > maxBlockBytes {
				return ErrFormat
			}
			if _, err := readFull(reader, int(length)-12); err != nil {
				return ErrFormat
			}
			section, interfaces = true, nil
			continue
		}
		if !section {
			return ErrFormat
		}
		kind := order.Uint32(head)
		length := order.Uint32(head[4:])
		if length < 12 || length%4 != 0 || length > maxBlockBytes {
			// A block that cannot be measured ends the reading; what was read stays.
			return nil
		}
		body, err := readFull(reader, int(length)-8)
		if err != nil {
			return nil
		}
		body = body[:len(body)-4]
		switch kind {
		case 1:
			if len(body) < 8 || len(interfaces) >= maxInterfaces {
				stats.Malformed++
				continue
			}
			found := pcapngInterface{linkType: uint32(order.Uint16(body)), tick: 1000}
			readOptions(body[8:], order, func(code uint16, value []byte) {
				if code == 9 && len(value) >= 1 {
					found.tick = resolution(value[0])
				}
			})
			interfaces = append(interfaces, found)
		case 6:
			if len(body) < 20 {
				stats.Malformed++
				number++
				continue
			}
			index := order.Uint32(body)
			captured := order.Uint32(body[12:])
			if int(index) >= len(interfaces) || captured > maxPacketBytes || int(captured) > len(body)-20 {
				stats.Malformed++
				number++
				continue
			}
			stamp := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
			current := interfaces[index]
			if err := each(packet{number: number, when: stampTime(stamp, current.tick), linkType: current.linkType, data: body[20 : 20+captured]}); err != nil {
				return err
			}
			number++
		case 3:
			stats.NoTime++
			number++
		}
		// Other blocks (names, statistics, custom blocks) carry no packets and are passed over.
	}
}

func readOptions(data []byte, order binary.ByteOrder, each func(code uint16, value []byte)) {
	for len(data) >= 4 {
		code, size := order.Uint16(data), int(order.Uint16(data[2:]))
		if code == 0 {
			return
		}
		padded := (size + 3) &^ 3
		if 4+padded > len(data) {
			return
		}
		each(code, data[4:4+size])
		data = data[4+padded:]
	}
}

// resolution gives the length of one tick in nanoseconds from the if_tsresol option: 10^-n seconds, or 2^-n
// seconds when the high bit is set.
func resolution(value byte) float64 {
	exponent := float64(value & 0x7f)
	if value&0x80 != 0 {
		return 1e9 / math.Pow(2, exponent)
	}

	return 1e9 / math.Pow(10, exponent)
}

func stampTime(stamp uint64, tick float64) time.Time {
	if tick <= 0 || math.IsInf(tick, 0) || math.IsNaN(tick) {
		return time.Unix(0, 0).UTC()
	}
	if tick >= 1 {
		ticksPerSecond := uint64(math.Round(1e9 / tick))
		if ticksPerSecond == 0 {
			ticksPerSecond = 1
		}
		seconds := stamp / ticksPerSecond
		if seconds > 1<<40 {
			return time.Unix(0, 0).UTC()
		}
		rest := stamp % ticksPerSecond

		return time.Unix(int64(seconds), int64(float64(rest)*tick)).UTC()
	}
	// Ticks shorter than a nanosecond: the stamp is cut to nanoseconds.
	nanos := float64(stamp) * tick
	if nanos > float64(math.MaxInt64) {
		return time.Unix(0, 0).UTC()
	}

	return time.Unix(0, int64(nanos)).UTC()
}

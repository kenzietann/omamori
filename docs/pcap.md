# Packet captures

`detect`, `analyze` and `rule draft` read packet captures: the pcap files of tcpdump and the pcapng files of
Wireshark. A capture is known by its first bytes, so its name does not matter and it can lie in a folder
with logs. `--format pcap` asks for it explicitly.

```sh
sudo tcpdump -i eth0 -w capture.pcap        # on a server you own, for as long as you want to look
omamori detect capture.pcap /var/log/auth.log
```

This stands in for tshark and the first step of Zeek: the capture becomes events of the same shape as Zeek
logs, and the same rules read them.

## What becomes an event

| `service` | One event for each | Fields |
|---|---|---|
| `conn` (category `network`) | TCP or UDP connection | `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`, `conn_state`, `bytes_sent`, `bytes_received`, `packets_sent`, `packets_received`, `app_protocol` (http, dns, tls), `tls_sni` |
| `http` (category `webserver`) | HTTP request | `method`, `url`, `http_host`, `user_agent`, `referrer`, `status` (from the answer) |
| `dns` (category `network`) | DNS question over UDP | `dns_query`, `dns_type`, `dns_rcode` (from the answer) |

Every event has `product: pcap`, so a rule or a person can tell it from Zeek. The originator of a connection
is the side that sent the first SYN (or, when the capture starts later, the side that got the SYN-ACK).
`conn_state` uses the names of Zeek: `S0` (no answer), `REJ` (refused), `S1` (open at the end), `SF` (closed
normally), `RSTO` and `RSTR` (reset by the originator or the responder), `OTH` (no start seen). The
reference of an event is the number of its first packet, as Wireshark counts them.

HTTP requests go to the web rules (scanners, injection, sensitive paths, web shell commands), connections to
the network rules (internal sweeps, port scans, large uploads), and every address and DNS name to the
indicator list (`--indicators`). The connection rules ask for `category: network` and `service: conn`, which
Zeek logs and captures both give.

## Safe to rely on

- **Every length is checked.** A capture is data from a network that someone else controls. Packets up to
  256 KB, blocks up to 1 MB, 5 million packets, 200,000 connections, 1 million events; more stops the run
  with a message, not with a partial answer. DNS names follow at most ten pointers and are at most 255 bytes.
- **Broken packets are counted, not guessed.** In the report a packet counts as a line: packets whose
  headers cannot be read are malformed, packets of other kinds (ARP, ICMP, fragments after the first, other
  link types) count as blank. A capture that was cut in its last packet is read up to the cut.
- **Text from packets is data.** Control characters are removed and values are cut at 2048 characters
  before they reach a rule, a report or the AI.
- A retransmitted request is counted once.
- Fuzzed: 11 million generated inputs, no crash, no value over its limit.

Link types: Ethernet (with up to two VLAN tags), Linux cooked (SLL and SLL2), raw IP, and the loopback of
BSD and macOS. IPv4 and IPv6 with extension headers. pcap in both byte orders, with micro- or nanosecond
times; pcapng with several sections and interfaces and every time resolution.

## Limits

- Only the first segment of an HTTP request is read: headers that come in a later packet, and request
  bodies, are not. HTTP/2, HTTP/3 and anything inside TLS cannot be read; for TLS only the server name of
  the ClientHello is kept.
- DNS over TCP, and answers (the addresses), are not read; the question and the code of the answer are.
- No reassembly of IP fragments; the first fragment is read, the others are counted.
- No protocols beyond TCP, UDP, HTTP, DNS and the TLS server name: no SMB, no SSH content, no ICMP events.
- A capture shows what passed one interface. A tcpdump on one server does not see the traffic of others.

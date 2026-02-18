# Plan: TCP Traffic Analyzer (`main.py`)

## Context

CSC 361 Assignment 2 requires building a Python program that reads a `.cap` (pcap) trace file, manually parses packet headers, reconstructs TCP connections, tracks state, computes statistics, and outputs results in a strict format. No code exists yet — the entire `main.py` must be created from scratch using only the Python standard library.

## File to Create

- `/Users/aryap/Desktop/uvic/spring26/csc361/a2/main.py` — single-file implementation

## Architecture

Single file with these logical sections: constants, parsing functions, connection tracking, statistics, output formatting.

### Key Data Structures

- **`Connection` class** — tracks per-connection state (src/dst IPs and ports, SYN/FIN/RST counts, packet/byte counts per direction, timing, window sizes, segments/ACKs for RTT)
- **`OrderedDict`** keyed by canonical 4-tuple — preserves insertion order for connection numbering

### Key Functions

| Function | Purpose |
|----------|---------|
| `parse_pcap(filename)` | Read file, detect endianness from magic number, iterate packet headers |
| `parse_ethernet(data, offset)` | Extract ethertype (filter for IPv4 = 0x0800) |
| `parse_ipv4(data, offset)` | Extract IPs, protocol (filter for TCP = 6), lengths (variable IHL) |
| `parse_tcp(data, offset)` | Extract ports, seq, ack, flags, window, data offset (variable header) |
| `get_connection_key()` | Canonical sorted 4-tuple so both directions map to same connection |
| `compute_rtt_for_direction()` | Match data segments with ACKs from opposite direction |
| `print_section_a/b/c/d()` | Output in exact required format |

## Implementation Steps

### 1. Pcap parsing
- Parse 24-byte global header; detect endianness from magic number (`0xa1b2c3d4` = little-endian, swapped = big-endian)
- **Pcap headers** use file endianness (`<` or `>`); **protocol headers** (Ethernet/IPv4/TCP) always use network byte order (`!`)
- Loop: read 16-byte packet header (timestamp, incl_len), then `incl_len` bytes of packet data
- Parse Ethernet (14 bytes) → IPv4 (variable: IHL*4 bytes) → TCP (variable: data_offset*4 bytes)
- Skip non-IPv4 or non-TCP packets
- Payload = `ip_total_length - ip_header_len - tcp_header_len` (clamp to 0)

### 2. Connection identification & source determination
- Canonical key: `tuple(sorted(((ip_a, port_a), (ip_b, port_b))))`
- Source determination: first pure SYN sender is source; if only SYN+ACK seen, the OTHER endpoint is source; if no SYN at all, first packet sender is source

### 3. Per-packet connection updates
- Increment SYN count if SYN flag set (SYN+ACK counts as SYN)
- Increment FIN count if FIN flag set
- Set RST flag if RST seen
- Track packet counts and data byte counts per direction
- Record all window sizes
- Store segments (timestamp, seq, payload_len) and ACKs (timestamp, ack_num) per direction for RTT
- Track `first_syn_time`, `last_fin_time`, `last_data_time`, `first_packet_has_syn`

### 4. Post-processing
- **Complete**: SYN count >= 1 AND FIN count >= 1
- **Still open**: `last_data_time > last_fin_time` (data after final FIN)
- **Established before capture**: first observed packet lacks SYN flag
- **Reset**: any packet has RST flag
- **Status string**: `S{syn_count}F{fin_count}`, append `/R` if RST seen

### 5. RTT calculation
- Per complete connection, per direction: match each data segment (payload > 0) with first ACK from opposite direction where `ack_num >= seq + payload_len` and `ack_ts >= seg_ts`
- One ACK can acknowledge multiple segments (cumulative ACKs — don't consume ACKs)
- Collect ALL RTT samples across all complete connections into one list
- Compute global min/mean/max

### 6. Output formatting (exact match required)
- **Section A**: Total connections count
- **Section B**: Per-connection details; note "Source Address" (capital A) vs "Destination address" (lowercase a), "End Time" (capital T); complete connections include timing/packet/byte stats; each block ends with `END` and `+++++++++++++++++++++++++++++++++`
- **Section C**: General stats (complete, reset, still open, established before capture)
- **Section D**: Aggregate stats over complete connections (duration, RTT, packets, window sizes) — all min/mean/max
- Time unit: seconds; float values with reasonable precision (6 decimal places)

## Edge Cases

- Variable-length IP and TCP headers (don't assume 20 bytes)
- SYN+ACK: counts as SYN for counting, but responder (not initiator) for source determination
- Negative payload: clamp to 0
- Connections with no data segments contribute 0 RTT samples
- Connections with no SYN: established before capture, source = first packet sender

## Verification

1. Run `python3 main.py sample-capture-file.cap` and check output structure matches the spec
2. Verify Section A connection count
3. Verify each connection's status string (S#F# format)
4. Verify complete connections have timing/byte stats, incomplete ones don't
5. Cross-check Section C counts (complete, reset, still open, before capture)
6. Verify RTT values are reasonable (positive, typically < 1 second)

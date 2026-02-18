# Implementation Phases for `main.py`

## Phase 1: Pcap File Parsing

**Goal:** Read the raw `.cap` file and extract individual packet bytes.

- Read the 24-byte **global header**; detect endianness from magic number
  - `0xa1b2c3d4` as little-endian → use `<` prefix for `struct`
  - `0xd4c3b2a1` as little-endian → use `>` prefix for `struct`
- Loop through the file reading each **packet record**:
  - 16-byte packet header → extract `ts_sec`, `ts_usec`, `incl_len`
  - Read `incl_len` bytes of raw packet data
- Compute **relative timestamp** for each packet: `(ts_sec + ts_usec/1e6) - capture_start`
- **Key rule:** Pcap headers use file endianness; protocol headers (Ethernet/IP/TCP) always use network byte order (`!`).

**Deliverable:** A list of `(relative_timestamp, raw_packet_bytes)` tuples.

---

## Phase 2: Protocol Header Parsing

**Goal:** Parse Ethernet → IPv4 → TCP headers from each packet's raw bytes.

- **Ethernet** (14 bytes): skip MACs, read ethertype. Filter for IPv4 (`0x0800`).
- **IPv4** (variable length): read IHL to get header length (`IHL * 4`). Extract `src_ip`, `dst_ip`, `protocol`, `total_length`. Filter for TCP (`protocol == 6`).
- **TCP** (variable length): read data offset to get header length (`data_offset * 4`). Extract `src_port`, `dst_port`, `seq`, `ack_num`, `flags`, `window`.
- Compute **payload length**: `ip_total_length - ip_header_len - tcp_header_len` (clamp to 0).
- Skip any packet that is not IPv4 or not TCP.

**Deliverable:** A list of parsed TCP packet records with all fields needed for connection tracking.

---

## Phase 3: Connection Identification & State Tracking

**Goal:** Group packets into TCP connections and track per-connection state.

- **Canonical key:** `tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))` so both directions map to the same connection.
- **Source determination:**
  - First pure SYN (SYN=1, ACK=0) sender → connection source
  - If only SYN+ACK seen → the OTHER endpoint is source
  - If no SYN at all → first packet sender is source
- **Per-packet updates:**
  - Increment `syn_count` if SYN flag set (SYN+ACK counts as SYN too)
  - Increment `fin_count` if FIN flag set
  - Set `rst_flag` if RST seen
  - Track `first_syn_time`, `last_fin_time`, `last_data_time`
  - Track whether the first observed packet has SYN (`first_packet_has_syn`)
  - Accumulate packet counts and data byte counts per direction
  - Record all window sizes
  - Store segments and ACKs per direction (for RTT in Phase 4)

**Deliverable:** An `OrderedDict` of `Connection` objects keyed by canonical 4-tuple, preserving insertion order.

---

## Phase 4: Statistics Computation

**Goal:** Derive all required statistics from the connection data.

### 4a: Connection Classification
- **Complete:** `syn_count >= 1` AND `fin_count >= 1`
- **Reset:** at least one packet has RST flag
- **Still open:** complete connection where `last_data_time > last_fin_time`
- **Established before capture:** first observed packet does NOT have SYN flag
- **Status string:** `S{syn_count}F{fin_count}`, append `/R` if RST seen

### 4b: RTT Calculation
- For each complete connection, per direction:
  - For each data segment (payload > 0), find the first ACK from the **opposite** direction where `ack_num >= seq + payload_len` and `ack_ts >= seg_ts`
  - RTT = `ack_ts - seg_ts`
  - Don't consume ACKs (cumulative ACKs can match multiple segments)
- Pool ALL RTT samples across all complete connections into one list
- Compute global min / mean / max

### 4c: Aggregate Stats (over complete connections only)
- **Duration:** min / mean / max of `(last_fin_time - first_syn_time)` per connection
- **Packets:** min / mean / max of total packet count per connection
- **Window sizes:** min / mean / max across ALL window values from ALL packets of complete connections

**Deliverable:** All values needed for Sections C and D of the output.

---

## Phase 5: Output Formatting

**Goal:** Print the four output sections in the exact format required.

### Section A
```
A) Total number of connections:
<count>
```

### Section B
For each connection (in order of first appearance):
```
Connection N:
Source Address: <ip>
Destination address: <ip>       ← lowercase 'a'
Source Port: <port>
Destination Port: <port>
Status: S#F#[/R]
```
If complete, also print:
```
Start time: <float> seconds
End Time: <float> seconds       ← capital 'T'
Duration: <float> seconds
Number of packets sent from Source to Destination: <int>
Number of packets sent from Destination to Source: <int>
Total number of packets: <int>
Number of data bytes sent from Source to Destination: <int>
Number of data bytes sent from Destination to Source: <int>
Total number of data bytes: <int>
```
Each connection ends with `END` then `+++++++++++++++++++++++++++++++++`.

### Section C
```
C) General

The total number of complete TCP connections: <int>
The number of reset TCP connections: <int>
The number of TCP connections that were still open when the trace capture ended: <int>
The number of TCP connections established before the capture started: <int>
```

### Section D
```
D) Complete TCP connections:

Minimum time duration: <float> seconds
Mean time duration: <float> seconds
Maximum time duration: <float> seconds

Minimum RTT value: <float> seconds
Mean RTT value: <float> seconds
Maximum RTT value: <float> seconds

Minimum number of packets including both send/received: <int>
Mean number of packets including both send/received: <float>
Maximum number of packets including both send/received: <int>

Minimum receive window size including both send/received: <int>
Mean receive window size including both send/received: <float>
Maximum receive window size including both send/received: <int>
```

**Deliverable:** Correctly formatted output to stdout.

---

## Phase 6: Testing & Edge Cases

**Goal:** Validate against the sample capture file and handle edge cases.

- Run `python3 main.py sample-capture-file.cap` and verify output structure
- Check connection count, status strings, timing, byte counts
- Edge cases to handle:
  - Variable-length IP/TCP headers (don't assume 20 bytes)
  - SYN+ACK: counts as SYN for counting, responder for source determination
  - Negative payload: clamp to 0
  - Connections with no data segments → 0 RTT samples
  - No complete connections → handle Section D gracefully

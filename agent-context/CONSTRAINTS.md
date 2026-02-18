# CONSTRAINTS.md  
CSC 361 – Assignment 2: TCP Traffic Analysis  

---

# 1. Environment Constraints

- The program **must run on** `linux.csc.uvic.ca`
- Only **Python 3 standard library packages** installed on that server may be used
- No third-party libraries allowed

## Not Allowed
- `scapy`
- `dpkt`
- Any `pip install`
- Any external packet parsing library

## Allowed
- `struct`
- `sys`
- `math`
- `collections`
- `statistics`
- `datetime`
- Any built-in Python3 modules

---

# 2. Execution Constraint

The program must run from the command line as:

```bash
python3 program.py <tracefile.cap>
```

- No hardcoded filenames  
- No interactive prompts  
- Must accept any valid `.cap` file as input  

---

# 3. Input Constraints

- Input file is a `.cap` (pcap format) file
- Must manually parse:
  - Global header
  - Packet headers
  - Ethernet II header
  - IPv4 header
  - TCP header
- Only TCP packets should be processed
- Non-TCP packets must be ignored

---

# 4. PCAP Parsing Constraints

- Endianness must be determined from the magic number in the global header
- Endianness applies to the entire file
- Multi-byte fields must respect file byte order
- Assume Ethernet II + IPv4 encapsulation
- Assume IPv4 only (not IPv6)

---

# 5. TCP Connection Constraints

A TCP connection is identified by a 4-tuple:

```
(Source IP, Source Port, Destination IP, Destination Port)
```

- The 4-tuple uniquely identifies a connection
- Packets from different connections may be interleaved
- Connections are duplex (packets flow both directions)

---

# 6. Connection State Constraints

Connection status must be reported as:

```
S#F#
```

Where:
- S = number of SYN segments seen
- F = number of FIN segments seen

Rules:

- SYN+ACK counts as a SYN
- RST indicates a reset connection
- A connection may have both S#F# and R

Examples:
- S1F0
- S2F2
- S3F1
- R

---

# 7. Definition Constraints

## Complete Connection

A connection is considered **complete** if:

- At least one SYN is observed  
- At least one FIN is observed  

It does NOT require:
- A full 3-way handshake
- Exactly two FINs

---

## Reset Connection

Count the number of connections that have **at least one RST flag**.

Do NOT count number of RST packets.

---

## Established Before Capture

If the first packet observed for a connection is NOT SYN,  
then the connection was established before capture.

---

## Still Open Connection

If data is observed after a FIN,  
the connection is considered still open.

---

# 8. Time Constraints

- Use **relative time** (time since beginning of capture)
- Do NOT use absolute timestamps
- Must print time unit (seconds or ms)

For complete connections:

- Start time = time of first SYN
- End time = time of last FIN
- Ignore whether FIN was acknowledged

---

# 9. Data Byte Constraints

- Data bytes must exclude:
  - Ethernet header
  - IP header
  - TCP header
- Only TCP payload bytes are counted

---

# 10. RTT Constraints

RTT calculation does not need to be perfect, but must be reasonable.

- Match data segments with corresponding ACKs
- Collect all RTT samples across all complete connections

When computing statistics:

- Min = minimum of all RTT samples
- Max = maximum of all RTT samples
- Mean = average of ALL RTT samples combined

Do NOT:
- Compute mean per connection and average those means

---

# 11. Statistical Constraints (Part D)

For complete connections only, compute:

- Minimum, mean, maximum duration
- Minimum, mean, maximum RTT
- Minimum, mean, maximum number of packets (both directions)
- Minimum, mean, maximum receive window size (both sides)

All means must be computed correctly across total values.
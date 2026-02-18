# OVERVIEW.md  
CSC 361 – Assignment 2: TCP Traffic Analysis  

---

# Overview

This assignment requires building a Python program that analyzes TCP traffic from a `.cap` (pcap) trace file.

The goal is to:

- Parse raw packet data
- Reconstruct TCP connections
- Track TCP state transitions
- Compute per-connection statistics
- Compute global statistics
- Output results in a strict required format

This project simulates building a simplified TCP traffic analyzer similar to a lightweight version of Wireshark.

---

# Core Objective

Given a TCP trace file:

```
python3 program.py <tracefile.cap>
```

Your program must:

1. Read and parse the pcap file manually
2. Extract and process only TCP packets
3. Identify connections using a 4-tuple
4. Track SYN, FIN, and RST flags
5. Determine connection states (S#F# and R)
6. Compute required statistics
7. Print output in the exact required format

---

# What You Are Building

You are implementing:

- A raw pcap parser
- A TCP connection tracker
- A TCP state analyzer
- A statistical summarizer

This involves understanding:

- Ethernet II framing
- IPv4 headers
- TCP headers
- TCP flags (SYN, ACK, FIN, RST)
- TCP handshake and teardown behavior
- RTT estimation
- Receive window tracking

---

# Key Concepts

## TCP Connection Identification

Each TCP connection is identified by a 4-tuple:

```
(Source IP, Source Port, Destination IP, Destination Port)
```

Packets from different connections may be interleaved.

---

## TCP State Tracking

For each connection, you must track:

- Number of SYN segments
- Number of FIN segments
- Presence of RST

Connection status is reported as:

```
S#F#
```

Where:
- S = number of SYNs seen
- F = number of FINs seen

RST indicates a reset connection.

---

## Complete Connections

A connection is considered complete if:

- At least one SYN is observed
- At least one FIN is observed

Only complete connections include timing and detailed statistics.

---

# Required Output Sections

The final output must contain:

- Total number of connections
- Detailed information for each connection
- General statistics
- Complete TCP connection statistics

The formatting must match the specification exactly.

---

# Technical Requirements

- Must manually parse the pcap file
- Must use only Python standard library
- Must handle endianness correctly
- Must process packets in order
- Must associate packets to correct connections
- Must compute statistics accurately

---

# Skills Being Tested

This assignment evaluates:

- Understanding of TCP protocol behavior
- Ability to parse binary file formats
- State tracking across interleaved data
- Accurate statistical computation
- Attention to strict formatting requirements

---

# High-Level Processing Flow

```
Read pcap file
    ↓
Parse global header
    ↓
For each packet:
    Parse packet header
    Parse Ethernet header
    Parse IPv4 header
    If TCP:
        Parse TCP header
        Identify connection
        Update connection state
    ↓
After processing:
    Compute statistics
    Print formatted output
```

---

# Summary

This assignment requires implementing a simplified TCP traffic analyzer from scratch.

It combines:

- Protocol-level reasoning
- Binary parsing
- State machine tracking
- Statistical analysis
- Strict output formatting

A correct solution must be both logically accurate and precisely formatted.
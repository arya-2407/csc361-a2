# OUTPUT-FORMAT.md  
CSC 361 – Assignment 2: TCP Traffic Analysis  

This document specifies the exact required output format for Assignment 2.  
Your program output must strictly follow this structure.

---

# A) Total Number of Connections

```
A) Total number of connections:
<integer>
```

---

# B) Connections' Details

For each TCP connection, print the following block.

```
B) Connections' details:

Connection 1:
Source Address: <IP>
Destination address: <IP>
Source Port: <port>
Destination Port: <port>
Status: <S#F# or R>

(Only if the connection is complete provide the following information)

Start time: <relative time> <unit>
End Time: <relative time> <unit>
Duration: <value> <unit>
Number of packets sent from Source to Destination: <integer>
Number of packets sent from Destination to Source: <integer>
Total number of packets: <integer>
Number of data bytes sent from Source to Destination: <integer>
Number of data bytes sent from Destination to Source: <integer>
Total number of data bytes: <integer>
END
+++++++++++++++++++++++++++++++++
```

Repeat this format for:

```
Connection 2:
...
Connection 3:
...
Connection N:
...
```

Each connection block must end with:

```
END
+++++++++++++++++++++++++++++++++
```

Notes:
- Only complete connections include timing, packet, and byte statistics.
- Incomplete connections include only the basic connection fields and Status.

---

# C) General Statistics

After listing all connections, print:

```
C) General

The total number of complete TCP connections: <integer>
The number of reset TCP connections: <integer>
The number of TCP connections that were still open when the trace capture ended: <integer>
The number of TCP connections established before the capture started: <integer>
```

---

# D) Complete TCP Connections Statistics

For complete TCP connections only, print:

```
D) Complete TCP connections:

Minimum time duration: <value> <unit>
Mean time duration: <value> <unit>
Maximum time duration: <value> <unit>

Minimum RTT value: <value> <unit>
Mean RTT value: <value> <unit>
Maximum RTT value: <value> <unit>

Minimum number of packets including both send/received: <integer>
Mean number of packets including both send/received: <value>
Maximum number of packets including both send/received: <integer>

Minimum receive window size including both send/received: <integer>
Mean receive window size including both send/received: <value>
Maximum receive window size including both send/received: <integer>
```

---

# Formatting Requirements

- Section labels (A, B, C, D) must appear exactly as shown.
- Field names must match exactly (including capitalization and spacing).
- Use relative time (not absolute timestamps).
- Include time units (seconds or milliseconds).
- Preserve spacing and structure.
- No additional commentary or debug prints.
- Output must be plain text only.
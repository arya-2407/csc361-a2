import struct
import sys
from collections import OrderedDict

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20

# Pcap
PCAP_GLOBAL_HEADER_LEN = 24
PCAP_PACKET_HEADER_LEN = 16
PCAP_MAGIC_LE = 0xa1b2c3d4
PCAP_MAGIC_BE = 0xd4c3b2a1

# Ethernet
ETHERNET_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800

# IP
IP_PROTOCOL_TCP = 6


# File Parsing

def parse_pcap(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    magic = struct.unpack('<I', data[0:4])[0]
    if magic == PCAP_MAGIC_LE:
        endian = '<'
    elif magic == PCAP_MAGIC_BE:
        endian = '>'
    else:
        magic_be = struct.unpack('>I', data[0:4])[0]
        if magic_be == PCAP_MAGIC_LE:
            endian = '>'
        else:
            raise ValueError(f"Unknown pcap magic number: {hex(magic)}")

    # Skip rest of global header, only needed endianness
    offset = PCAP_GLOBAL_HEADER_LEN

    packets = []
    capture_start = None

    while offset + PCAP_PACKET_HEADER_LEN <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            endian + 'IIII', data[offset:offset + PCAP_PACKET_HEADER_LEN]
        )
        offset += PCAP_PACKET_HEADER_LEN

        if offset + incl_len > len(data):
            break
        raw_bytes = data[offset:offset + incl_len]
        offset += incl_len

        # Compute absolute timestamp, then relative to capture start
        abs_time = ts_sec + ts_usec / 1_000_000.0

        if capture_start is None:
            capture_start = abs_time

        rel_time = abs_time - capture_start
        packets.append((rel_time, raw_bytes))

    return capture_start, packets


# Protocol Header Parsing

def format_ip(raw_bytes):
    return '.'.join(str(b) for b in raw_bytes)


def parse_ethernet(pkt, offset):
    if offset + ETHERNET_HEADER_LEN > len(pkt):
        return None
    # Ethertype is always network byte order
    ethertype = struct.unpack('!H', pkt[offset + 12:offset + 14])[0]
    return ethertype, offset + ETHERNET_HEADER_LEN


def parse_ipv4(pkt, offset):
    if offset + 20 > len(pkt):
        return None
    version_ihl = pkt[offset]
    ihl = version_ihl & 0x0F
    ip_hdr_len = ihl * 4
    if ip_hdr_len < 20 or offset + ip_hdr_len > len(pkt):
        return None
    ip_total_len = struct.unpack('!H', pkt[offset + 2:offset + 4])[0]
    protocol = pkt[offset + 9]
    src_ip = format_ip(pkt[offset + 12:offset + 16])
    dst_ip = format_ip(pkt[offset + 16:offset + 20])
    return src_ip, dst_ip, protocol, ip_total_len, ip_hdr_len, offset + ip_hdr_len


def parse_tcp(pkt, offset):
    if offset + 20 > len(pkt):
        return None
    src_port = struct.unpack('!H', pkt[offset:offset + 2])[0]
    dst_port = struct.unpack('!H', pkt[offset + 2:offset + 4])[0]
    seq = struct.unpack('!I', pkt[offset + 4:offset + 8])[0]
    ack_num = struct.unpack('!I', pkt[offset + 8:offset + 12])[0]
    data_off_flags = struct.unpack('!H', pkt[offset + 12:offset + 14])[0]
    data_offset = (data_off_flags >> 12) & 0x0F
    flags = data_off_flags & 0x3F
    window = struct.unpack('!H', pkt[offset + 14:offset + 16])[0]
    tcp_hdr_len = data_offset * 4
    if tcp_hdr_len < 20 or offset + tcp_hdr_len > len(pkt):
        return None
    return src_port, dst_port, seq, ack_num, flags, window, tcp_hdr_len, offset + tcp_hdr_len


def parse_packets(raw_packets):
    tcp_packets = []
    for rel_time, pkt in raw_packets:
        # Ethernet
        eth = parse_ethernet(pkt, 0)
        if eth is None or eth[0] != ETHERTYPE_IPV4:
            continue

        # IPv4
        ip = parse_ipv4(pkt, eth[1])
        if ip is None or ip[2] != IP_PROTOCOL_TCP:
            continue
        src_ip, dst_ip, protocol, ip_total_len, ip_hdr_len, tcp_offset = ip

        # TCP
        tcp = parse_tcp(pkt, tcp_offset)
        if tcp is None:
            continue
        src_port, dst_port, seq, ack_num, flags, window, tcp_hdr_len, _ = tcp

        # Payload = IP total length - IP header - TCP header (clamp to 0)
        payload_len = max(0, ip_total_len - ip_hdr_len - tcp_hdr_len)

        tcp_packets.append({
            'timestamp': rel_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'seq': seq,
            'ack_num': ack_num,
            'flags': flags,
            'window': window,
            'payload_len': payload_len,
        })

    return tcp_packets

# manage state
class Connection:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # State tracking
        self.syn_count = 0
        self.fin_count = 0
        self.rst_flag = False
        self.source_determined_by_syn = False

        # Packet and byte counts per direction
        self.packets_src_to_dst = 0
        self.packets_dst_to_src = 0
        self.bytes_src_to_dst = 0
        self.bytes_dst_to_src = 0

        # Timing
        self.first_syn_time = None
        self.last_fin_time = None
        self.last_data_time = None
        self.first_packet_has_syn = False

        # Window sizes (all packets)
        self.window_sizes = []

        # RTT data: segments and ACKs per direction
        self.src_segments = []   # (timestamp, seq, payload_len) from src->dst
        self.dst_segments = []   # (timestamp, seq, payload_len) from dst->src
        self.src_acks = []       # (timestamp, ack_num) from src (acknowledging dst's data)
        self.dst_acks = []       # (timestamp, ack_num) from dst (acknowledging src's data)


def get_connection_key(src_ip, src_port, dst_ip, dst_port):
    return tuple(sorted(((src_ip, src_port), (dst_ip, dst_port))))


def is_from_source(pkt, conn):
    return pkt['src_ip'] == conn.src_ip and pkt['src_port'] == conn.src_port


def build_connections(tcp_packets):
    connections = OrderedDict()

    for pkt in tcp_packets:
        key = get_connection_key(pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
        flags = pkt['flags']
        ts = pkt['timestamp']
        payload = pkt['payload_len']

        if key not in connections:
            conn = Connection(pkt['src_ip'], pkt['src_port'], pkt['dst_ip'], pkt['dst_port'])
            conn.first_packet_has_syn = bool(flags & SYN)
            connections[key] = conn
        conn = connections[key]

        if (flags & SYN) and not conn.source_determined_by_syn:
            if (flags & SYN) and not (flags & ACK):
                conn.src_ip = pkt['src_ip']
                conn.src_port = pkt['src_port']
                conn.dst_ip = pkt['dst_ip']
                conn.dst_port = pkt['dst_port']
            elif (flags & SYN) and (flags & ACK):
                conn.src_ip = pkt['dst_ip']
                conn.src_port = pkt['dst_port']
                conn.dst_ip = pkt['src_ip']
                conn.dst_port = pkt['src_port']
            conn.source_determined_by_syn = True

        from_src = is_from_source(pkt, conn)

        if flags & SYN:
            conn.syn_count += 1
            if conn.first_syn_time is None:
                conn.first_syn_time = ts

        if flags & FIN:
            conn.fin_count += 1
            conn.last_fin_time = ts

        if flags & RST:
            conn.rst_flag = True

        if from_src:
            conn.packets_src_to_dst += 1
            conn.bytes_src_to_dst += payload
        else:
            conn.packets_dst_to_src += 1
            conn.bytes_dst_to_src += payload

        if payload > 0:
            conn.last_data_time = ts

        conn.window_sizes.append(pkt['window'])

        if from_src:
            if payload > 0:
                conn.src_segments.append((ts, pkt['seq'], payload))
            if flags & ACK:
                conn.src_acks.append((ts, pkt['ack_num']))
        else:
            if payload > 0:
                conn.dst_segments.append((ts, pkt['seq'], payload))
            if flags & ACK:
                conn.dst_acks.append((ts, pkt['ack_num']))

    return connections



# Statistics Computation
def is_complete(conn):
    return conn.syn_count >= 1 and conn.fin_count >= 1


def status_string(conn):
    s = f"S{conn.syn_count}F{conn.fin_count}"
    if conn.rst_flag:
        s += "/R"
    return s


def is_still_open(conn):
    if conn.last_fin_time is None or conn.last_data_time is None:
        return False
    return conn.last_data_time > conn.last_fin_time


def is_established_before_capture(conn):
    return not conn.first_packet_has_syn


def compute_rtt_for_direction(segments, acks):
    rtt_samples = []
    for seg_ts, seg_seq, seg_len in segments:
        needed_ack = seg_seq + seg_len
        for ack_ts, ack_num in acks:
            if ack_ts >= seg_ts and ack_num >= needed_ack:
                rtt_samples.append(ack_ts - seg_ts)
                break
    return rtt_samples


def compute_all_rtt(connections):
    all_rtt = []
    for conn in connections.values():
        if not is_complete(conn):
            continue
        all_rtt.extend(compute_rtt_for_direction(conn.src_segments, conn.dst_acks))
        all_rtt.extend(compute_rtt_for_direction(conn.dst_segments, conn.src_acks))
    return all_rtt


def compute_general_stats(connections):
    complete = 0
    reset = 0
    still_open = 0
    before_capture = 0
    for conn in connections.values():
        if is_complete(conn):
            complete += 1
        if conn.rst_flag:
            reset += 1
        if is_still_open(conn):
            still_open += 1
        if is_established_before_capture(conn):
            before_capture += 1
    return {
        'complete': complete,
        'reset': reset,
        'still_open': still_open,
        'before_capture': before_capture,
    }


def compute_complete_stats(connections):
    durations = []
    packet_counts = []
    all_windows = []

    for conn in connections.values():
        if not is_complete(conn):
            continue
        duration = conn.last_fin_time - conn.first_syn_time
        durations.append(duration)
        packet_counts.append(conn.packets_src_to_dst + conn.packets_dst_to_src)
        all_windows.extend(conn.window_sizes)

    all_rtt = compute_all_rtt(connections)

    def min_mean_max(values):
        if not values:
            return 0, 0, 0
        return min(values), sum(values) / len(values), max(values)

    return {
        'duration': min_mean_max(durations),
        'rtt': min_mean_max(all_rtt),
        'packets': min_mean_max(packet_counts),
        'window': min_mean_max(all_windows),
    }


# Format Output

SEPARATOR = "+++++++++++++++++++++++++++++++++"


def print_section_a(connections):
    print("A) Total number of connections:")
    print(len(connections))


def print_section_b(connections):
    print("B) Connections' details:")
    print()
    for i, conn in enumerate(connections.values(), 1):
        print(f"Connection {i}:")
        print(f"Source Address: {conn.src_ip}")
        print(f"Destination address: {conn.dst_ip}")
        print(f"Source Port: {conn.src_port}")
        print(f"Destination Port: {conn.dst_port}")
        print(f"Status: {status_string(conn)}")
        if is_complete(conn):
            start = conn.first_syn_time
            end = conn.last_fin_time
            duration = end - start
            total_pkts = conn.packets_src_to_dst + conn.packets_dst_to_src
            total_bytes = conn.bytes_src_to_dst + conn.bytes_dst_to_src
            print(f"Start time: {start:.6f} seconds")
            print(f"End Time: {end:.6f} seconds")
            print(f"Duration: {duration:.6f} seconds")
            print(f"Number of packets sent from Source to Destination: {conn.packets_src_to_dst}")
            print(f"Number of packets sent from Destination to Source: {conn.packets_dst_to_src}")
            print(f"Total number of packets: {total_pkts}")
            print(f"Number of data bytes sent from Source to Destination: {conn.bytes_src_to_dst}")
            print(f"Number of data bytes sent from Destination to Source: {conn.bytes_dst_to_src}")
            print(f"Total number of data bytes: {total_bytes}")
        print("END")
        print(SEPARATOR)


def print_section_c(connections):
    general = compute_general_stats(connections)
    print("C) General")
    print()
    print(f"The total number of complete TCP connections: {general['complete']}")
    print(f"The number of reset TCP connections: {general['reset']}")
    print(f"The number of TCP connections that were still open when the trace capture ended: {general['still_open']}")
    print(f"The number of TCP connections established before the capture started: {general['before_capture']}")


def print_section_d(connections):
    stats = compute_complete_stats(connections)
    dur = stats['duration']
    rtt = stats['rtt']
    pkts = stats['packets']
    win = stats['window']

    print("D) Complete TCP connections:")
    print()
    print(f"Minimum time duration: {dur[0]:.6f} seconds")
    print(f"Mean time duration: {dur[1]:.6f} seconds")
    print(f"Maximum time duration: {dur[2]:.6f} seconds")
    print()
    print(f"Minimum RTT value: {rtt[0]:.6f} seconds")
    print(f"Mean RTT value: {rtt[1]:.6f} seconds")
    print(f"Maximum RTT value: {rtt[2]:.6f} seconds")
    print()
    print(f"Minimum number of packets including both send/received: {pkts[0]}")
    print(f"Mean number of packets including both send/received: {pkts[1]:.6f}")
    print(f"Maximum number of packets including both send/received: {pkts[2]}")
    print()
    print(f"Minimum receive window size including both send/received: {win[0]}")
    print(f"Mean receive window size including both send/received: {win[1]:.6f}")
    print(f"Maximum receive window size including both send/received: {win[2]}")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <tracefile.cap>")
        sys.exit(1)

    capture_start, raw_packets = parse_pcap(sys.argv[1])
    tcp_packets = parse_packets(raw_packets)
    connections = build_connections(tcp_packets)

    print_section_a(connections)
    print()
    print_section_b(connections)
    print()
    print_section_c(connections)
    print()
    print_section_d(connections)

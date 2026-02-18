Usage:
python3 main.py <cap-file.cap>

This program writes the output to stdout (the terminal).

If you wish to read the output in a file, run:

python3 main.py <cap-file.cap> > output.txt

this will output the content in output.txt

Implementation Approach:

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

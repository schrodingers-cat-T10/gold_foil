import pyshark

class babyshark:

    def capture_live(interface, packet_count=10):
        capture = pyshark.LiveCapture(interface=interface)
        print(f"Capturing {packet_count} packets on {interface}...")
        capture.sniff(packet_count=packet_count)
        listing=[]
        for packet in capture:
            list.append(packet)
        return listing

    def filter_packets(interface, display_filter, packet_count=10):

        capture = pyshark.LiveCapture(interface=interface, display_filter=display_filter)
        print(f"Capturing {packet_count} packets with filter '{display_filter}'...")
        capture.sniff(packet_count=packet_count)
        listing=[]
        for packet in capture:
            list.append(packet)
        return listing

    def extract_ip_addresses(interface, packet_count=10):
        capture = pyshark.LiveCapture(interface=interface)
        capture.sniff(packet_count=packet_count)
        ip_addresses = set()
        for packet in capture:
            if hasattr(packet, 'ip'):
                ip_addresses.add(packet.ip.src)
                ip_addresses.add(packet.ip.dst)
        return ip_addresses

    def detect_http_requests(interface, packet_count=10):
        capture = pyshark.LiveCapture(interface=interface, display_filter="http")
        capture.sniff(packet_count=packet_count)
        listing=[]
        for packet in capture:
            list.append(packet)
        return listing

    def detect_dns_queries(interface, packet_count=10):
        capture = pyshark.LiveCapture(interface=interface, display_filter="dns")
        capture.sniff(packet_count=packet_count)
        listing=[]
        for packet in capture:
            list.append(packet)
        return listing

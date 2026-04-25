"""
Creates a safe, fake lab PCAP for testing the sniffer.

This PCAP includes:
- A fake DNS query packet
- A fake HTTP request packet with fake sensitive values

The sensitive values are intentionally fake and should be redacted by sniffer.py.
"""

from pathlib import Path

from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, Raw, wrpcap


def main():
    samples_dir = Path("samples")
    samples_dir.mkdir(exist_ok=True)

    dns_packet = (
        Ether()
        / IP(src="192.168.1.25", dst="8.8.8.8")
        / UDP(sport=53533, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="example.com"))
    )

    http_payload = (
        b"GET /login?email=student@example.com&token=abc123&password=fakepass HTTP/1.1\r\n"
        b"Host: lab.local\r\n"
        b"Authorization: Bearer fake-secret-token\r\n"
        b"Cookie: sessionid=fake-cookie-value\r\n"
        b"\r\n"
    )

    http_packet = (
        Ether()
        / IP(src="192.168.1.25", dst="93.184.216.34")
        / TCP(sport=55555, dport=80, flags="PA", seq=1, ack=1)
        / Raw(load=http_payload)
    )

    output_path = samples_dir / "lab_test.pcap"
    wrpcap(str(output_path), [dns_packet, http_packet])

    print(f"Created sample PCAP: {output_path}")


if __name__ == "__main__":
    main()

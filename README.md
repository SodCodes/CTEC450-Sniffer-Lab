Ethical Packet Sniffer
Project Overview



This is an educational packet sniffer for studying network protocols in a controlled lab environment. It reads packets from PCAP files or captures from authorized lab interfaces, decodes network protocols, and redacts sensitive data before output.



The tool supports two modes:

- **PCAP mode:** Read packets from existing `.pcap` or `.pcapng` files
- **Live mode:** Capture from authorized lab interfaces (loopback only by default)



Learning Goals



- Understand how packet capture and protocol analysis work
- Decode packet headers for Ethernet, IP, TCP, UDP, DNS, and HTTP
- Apply data redaction techniques for sensitive information
- Recognize security implications of network tools



\## Setup



Install dependencies:

```bash
py -m pip install -r requirements.txt
```

Or install manually:

```bash
py -m pip install scapy pytest
```

**Note:** On Windows, live capture requires Npcap.

**File Structure**

```
sniffer_lab/
├── sniffer.py              # Main packet sniffer tool
├── sample_pcap.py          # Script to generate test PCAP files
├── README.md
├── requirements.txt
├── samples/
│   └── lab_test.pcap       # Sample traffic for testing
└── tests/
    ├── test_redaction.py
    └── test_http_parsing.py
```

## Usage

**Run tests:**

```bash
py -m pytest
```

**Generate sample PCAP file:**

```bash
py sample_pcap.py
```

**Analyze PCAP file:**

```bash
py sniffer.py --mode pcap --pcap samples/lab_test.pcap --filter "tcp port 80 or udp port 53" --count 25 --out output/packets.jsonl
```

**List available interfaces:**

```bash
py sniffer.py --list-interfaces
```

**Capture from loopback interface:**

```bash
py sniffer.py --mode live --iface "NPF_Loopback" --allow-iface "NPF_Loopback" --filter "tcp port 8000" --count 25 --out output/loopback_http.jsonl
```



To generate test traffic, start a local server:

```bash
py -m http.server 8000
```

Then access it locally:

```
http://127.0.0.1:8000/?email=student@example.com&token=fake123
```

## Data Redaction

The tool automatically redacts sensitive data before output:

- IPv4 addresses → `192.168.1.xxx`
- Email addresses → `[REDACTED_EMAIL]`
- Authorization headers
- Cookie and Set-Cookie headers
- Query parameters: `password`, `token`, `secret`, `session`, `auth`, `api_key`



## Ethical Use

This tool is intended **only for authorized lab traffic** in an educational setting. Use it to:
- Analyze your own network traffic
- Study protocol fundamentals in a controlled lab environment
- Learn about data security and redaction techniques

If live capture privileges are unavailable, use PCAP mode with existing lab traffic instead.



AI Use Policy



Use Copilot for:



boilerplate, CLI parsing, JSON formatting, unit test scaffolds



Do not ask Copilot for:



capturing “other people’s traffic”

bypassing OS permissions

stealth features, persistence, or hiding activity



Always:



add interface/pcap allowlist

include redaction

default to pcap mode if capture privileges are missing


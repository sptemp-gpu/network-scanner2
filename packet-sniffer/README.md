# 🔍 Packet Sniffer & Analyzer

A real-time ethical hacking tool built in Python using Scapy. It captures network traffic, analyzes packet info, detects suspicious behavior (like port scanning), and logs useful data.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 🚀 Features

- 📡 Real-time packet sniffing using `scapy`
- 📄 Save logs with timestamp, protocol, IPs
- 🕵️ Detects potential port scans
- 🔍 Filter by protocol: `TCP`, `UDP`, or `ICMP`
- ⚙️ Command-line options for flexibility

---

## 🖥️ Usage

### 📦 Install Requirements
```bash
pip install -r requirements.txt
```

### ▶️ Run the Tool

| Description | Command |
|------------|---------|
| Live packets only | `sudo python3 sniffer.py --live` |
| Save logs only | `sudo python3 sniffer.py --save` |
| Filter TCP | `sudo python3 sniffer.py --filter tcp` |
| Full mode | `sudo python3 sniffer.py --live --save` |

Logs saved to `logs/packet_log.txt`

---

## 🛡️ Legal Disclaimer

This tool is made for **educational purposes** only. Do not use it on networks without permission.

---

## 📜 License

This project is under the [MIT License](LICENSE).

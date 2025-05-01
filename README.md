# 🛡️ Advanced Trojan PCAP Analyzer

A Python-based PCAP analysis tool to detect potential Trojan activity and malware behaviors using passive traffic inspection. It identifies suspicious downloads, DNS tunneling, beaconing patterns, non-standard port usage, and base64-encoded payloads—presented in a clean HTML report.

---

## 🚀 Features

- 🧠 Intelligent detection of suspicious HTTP downloads (`.exe`, `.dll`, `.scr`, `.bat`)
- 📡 Beaconing pattern recognition (C2-like communications)
- 🌐 DNS tunneling detection via entropy analysis and subdomain depth
- 🧬 Base64 payload extraction from HTTP traffic
- 🚧 Alerts on non-standard port usage
- 🧪 Packet size clustering for anomaly detection
- 📑 Clean HTML report generation (no graph output)

---

## 📦 Requirements

- Python 3.9+
- `pyshark`
- `scikit-learn`
- `tshark` (installed and added to PATH)

Install dependencies:

```bash
pip install -r requirements.txt
⚙️ Usage
Place your .pcap or .pcapng file in the pcaps/ directory.

Run the analyzer:

bash
Copy
Edit
python scanner.py pcaps/your_file.pcapng
Output:

The tool logs progress in the terminal.

Results are saved to: advanced_trojan_analysis_report.html

Open the HTML file in a browser to view the findings.

📁 Output Contents
Suspicious file download summary

DNS anomalies (entropy and depth)

Beaconing indicators

Base64 payload samples (truncated)

Non-standard ports list

Anomaly clusters (if found)

🔒 Disclaimer
This tool is intended for educational and research purposes. It does not perform full payload sandboxing or APT detection. Use responsibly.

```
#
👤 Author
Sujal Lamichhane
Cybersecurity & Forensics Researcher


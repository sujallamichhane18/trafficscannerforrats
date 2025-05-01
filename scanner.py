import pyshark
import re
import json
import hashlib
from collections import defaultdict, Counter
from datetime import datetime
from sklearn.cluster import KMeans
import warnings
import os

# OPTIONAL: Clear terminal
os.system('cls' if os.name == 'nt' else 'clear')

# Suppress joblib warnings
warnings.filterwarnings("ignore", category=UserWarning, module='joblib')

# Check if string is base64
def is_base64(s):
    return bool(re.match(r'^[A-Za-z0-9+/=]{20,}$', s))

# Basic entropy calculator
def calculate_entropy(data):
    entropy = 0
    for c in set(data):
        p = float(data.count(c)) / len(data)
        entropy -= p * (p ** 0.5)
    return entropy

# Analyze the PCAP file
def analyze_pcap(pcap_file):
    print("[>] Starting Trojan Analysis...")
    print(f"[+] Loaded PCAP file: {pcap_file}")
    print("[*] Analyzing packets...")

    capture = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)

    suspicious_downloads = []
    dns_tunnel_detected = []
    beacon_ips = defaultdict(list)
    non_standard_ports = Counter()
    encoded_payloads = []

    exe_pattern = re.compile(r'\.exe|\.dll|\.bat|\.scr', re.IGNORECASE)
    b64_pattern = re.compile(r'([A-Za-z0-9+/]{20,}={0,2})')

    for packet in capture:
        try:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            timestamp = packet.sniff_time.isoformat()

            # HTTP Download Detection
            if "HTTP" in packet:
                if hasattr(packet.http, "request_uri"):
                    uri = packet.http.request_uri
                    if exe_pattern.search(uri):
                        suspicious_downloads.append({
                            "source": ip_src, "destination": ip_dst,
                            "uri": uri, "timestamp": timestamp
                        })
                if hasattr(packet.http, "file_data"):
                    payload = packet.http.file_data
                    if b64_pattern.search(payload):
                        encoded_payloads.append({
                            "source": ip_src, "destination": ip_dst,
                            "encoded_data": payload[:80], "timestamp": timestamp
                        })

            # DNS Tunneling Detection
            if "DNS" in packet:
                dns_query = str(packet.dns.qry_name)
                entropy = calculate_entropy(dns_query)
                if len(dns_query.split(".")) > 5 or entropy > 3.5:
                    dns_tunnel_detected.append({
                        "source": ip_src, "query": dns_query, "timestamp": timestamp
                    })

            # Beaconing Detection
            beacon_ips[ip_dst].append(packet.sniff_time)

            # Non-Standard Port Detection
            if "TCP" in packet:
                dst_port = int(packet.tcp.dstport)
                if dst_port not in [80, 443, 53, 22]:
                    non_standard_ports[dst_port] += 1

        except AttributeError:
            continue

    packet_lengths = [int(packet.length) for packet in capture if hasattr(packet, 'length')]
    kmeans = KMeans(n_clusters=3)
    clusters = kmeans.fit_predict([[length] for length in packet_lengths])

    report = {
        "summary": {
            "total_http_downloads": len(suspicious_downloads),
            "total_dns_tunnel_suspicions": len(dns_tunnel_detected),
            "total_beacon_ips": len(beacon_ips),
            "non_standard_ports": dict(non_standard_ports),
            "encoded_payloads_detected": len(encoded_payloads),
            "cluster_centroids": kmeans.cluster_centers_.tolist(),
            "generated_at": datetime.utcnow().isoformat()
        },
        "suspicious_downloads": suspicious_downloads,
        "dns_tunneling": dns_tunnel_detected,
        "beaconing": beacon_ips,
        "encoded_payloads": encoded_payloads
    }

    html_report = generate_html_report(report)
    output_file = "advanced_trojan_analysis_report.html"
    with open(output_file, "w") as f:
        f.write(html_report)

    print("[✔] Analysis complete.")
    print(f"[💾] Report saved: {output_file}")
    print("[✦] Exiting...\n")

# HTML Report Generator
def generate_html_report(report):
    html_template = """
    <html>
    <head>
        <title>Advanced Trojan Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f7fa; }}
            h1, h2 {{ color: #2a6eb5; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f2f2f2; }}
            .section {{ margin-top: 30px; }}
            .alert {{ color: red; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>Advanced Trojan Analysis Report</h1>
        <h2>Summary</h2>
        <p><strong>Total HTTP Downloads:</strong> {total_http_downloads}</p>
        <p><strong>Total DNS Tunnel Suspicions:</strong> {total_dns_tunnel_suspicions}</p>
        <p><strong>Total Beacon IPs:</strong> {total_beacon_ips}</p>
        <p><strong>Non-Standard Ports Detected:</strong> {non_standard_ports}</p>
        <p><strong>Encoded Payloads Detected:</strong> {encoded_payloads_detected}</p>
        <p><strong>Cluster Centroids (Packet Length):</strong> {cluster_centroids}</p>
        <p><strong>Generated At:</strong> {generated_at}</p>

        <div class="section">
            <h3>Suspicious Downloads</h3>
            {suspicious_downloads_table}
        </div>
        <div class="section">
            <h3>DNS Tunneling</h3>
            {dns_tunneling_table}
        </div>
        <div class="section">
            <h3>Beaconing IPs</h3>
            {beacon_ips_table}
        </div>
        <div class="section">
            <h3>Encoded Payloads</h3>
            {encoded_payloads_table}
        </div>
    </body>
    </html>
    """

    suspicious_downloads_table = "<table><tr><th>Source IP</th><th>Destination IP</th><th>URI</th><th>Timestamp</th></tr>"
    for item in report["suspicious_downloads"]:
        suspicious_downloads_table += f"<tr><td>{item['source']}</td><td>{item['destination']}</td><td>{item['uri']}</td><td>{item['timestamp']}</td></tr>"
    suspicious_downloads_table += "</table>"

    dns_tunneling_table = "<table><tr><th>Source IP</th><th>DNS Query</th><th>Timestamp</th></tr>"
    for item in report["dns_tunneling"]:
        dns_tunneling_table += f"<tr><td>{item['source']}</td><td>{item['query']}</td><td>{item['timestamp']}</td></tr>"
    dns_tunneling_table += "</table>"

    beacon_ips_table = "<table><tr><th>Beaconing IP</th><th>Packet Count</th></tr>"
    for ip, times in report["beaconing"].items():
        beacon_ips_table += f"<tr><td>{ip}</td><td>{len(times)}</td></tr>"
    beacon_ips_table += "</table>"

    encoded_payloads_table = "<table><tr><th>Source IP</th><th>Encoded Payload</th><th>Timestamp</th></tr>"
    for item in report["encoded_payloads"]:
        encoded_payloads_table += f"<tr><td>{item['source']}</td><td>{item['encoded_data']}</td><td>{item['timestamp']}</td></tr>"
    encoded_payloads_table += "</table>"

    return html_template.format(
        total_http_downloads=report["summary"]["total_http_downloads"],
        total_dns_tunnel_suspicions=report["summary"]["total_dns_tunnel_suspicions"],
        total_beacon_ips=report["summary"]["total_beacon_ips"],
        non_standard_ports=json.dumps(report["summary"]["non_standard_ports"], indent=4),
        encoded_payloads_detected=report["summary"]["encoded_payloads_detected"],
        cluster_centroids=report["summary"]["cluster_centroids"],
        generated_at=report["summary"]["generated_at"],
        suspicious_downloads_table=suspicious_downloads_table,
        dns_tunneling_table=dns_tunneling_table,
        beacon_ips_table=beacon_ips_table,
        encoded_payloads_table=encoded_payloads_table
    )

# Entry point
if __name__ == "__main__":
    analyze_pcap("pcaps/test.pcapng")

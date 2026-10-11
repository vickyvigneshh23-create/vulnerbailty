#!/usr/bin/env python3
"""
Vulnerability Scanner (Mini Project)
A beginner-friendly, permission-based checker for a host you own or are
explicitly authorized to assess.

Checks:
- DNS resolution
- A small set of common TCP ports
- Basic HTTP security headers (only when HTTP/HTTPS is enabled)
- HTTP response information

This is a lightweight educational checker, not a full vulnerability scanner.
"""

import argparse
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP alternate",
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Helps enforce HTTPS on supported browsers.",
    "Content-Security-Policy": "Helps reduce certain cross-site scripting risks.",
    "X-Content-Type-Options": "Use 'nosniff' to reduce MIME-sniffing risks.",
    "X-Frame-Options": "Helps control framing and clickjacking exposure.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
}


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        print(f"[ERROR] Could not resolve host '{host}': {exc}")
        return None


def check_ports(host, ports, timeout):
    print("\n[1] TCP PORT CHECK")
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = COMMON_PORTS.get(port, "Unknown service")
                    print(f"[OPEN] {port}/tcp - {service}")
                    open_ports.append(port)
        except (socket.timeout, OSError):
            continue

    if not open_ports:
        print("No checked TCP ports were found open.")
    return open_ports


def fetch_headers(url, timeout):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Educational-Vulnerability-Scanner/1.0"},
        method="GET",
    )
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.headers, response.geturl()
    except urllib.error.HTTPError as exc:
        # HTTP error responses still include useful response headers.
        return exc.code, exc.headers, url
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        print(f"[INFO] Could not retrieve web headers from {url}: {exc}")
        return None, None, url


def check_web_headers(host, timeout):
    print("\n[2] WEB SECURITY HEADER CHECK")
    urls = [f"https://{host}", f"http://{host}"]
    for url in urls:
        status, headers, final_url = fetch_headers(url, timeout)
        if headers is None:
            continue

        print(f"URL: {final_url}")
        print(f"HTTP status: {status}")
        missing = []
        for header, explanation in SECURITY_HEADERS.items():
            if header.lower() not in {key.lower() for key in headers.keys()}:
                print(f"[REVIEW] Missing {header} - {explanation}")
                missing.append(header)
            else:
                print(f"[OK] {header} present")

        if url.startswith("http://"):
            print("[REVIEW] HTTP was reachable; use HTTPS for sites that handle sensitive data.")
        if not missing:
            print("All headers in this basic checklist were present.")
        return
    print("No HTTP/HTTPS response was available for header inspection.")


def main():
    parser = argparse.ArgumentParser(
        description="Basic vulnerability checks for a host you are authorized to test."
    )
    parser.add_argument(
        "host",
        help="Hostname or IP address you own or have explicit permission to assess",
    )
    parser.add_argument(
        "--ports",
        default="21,22,23,25,53,80,110,139,143,443,445,3306,3389,5432,8080",
        help="Comma-separated TCP ports to check (default: common ports)",
    )
    parser.add_argument("--timeout", type=float, default=0.7, help="Connection timeout in seconds")
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        ports = sorted({int(item.strip()) for item in args.ports.split(",") if item.strip()})
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError
    except ValueError:
        parser.error("--ports must be a comma-separated list of port numbers from 1 to 65535")

    print("=" * 60)
    print(" VULNERABILITY SCANNER - EDUCATIONAL MINI PROJECT")
    print("=" * 60)
    print(f"Started: {datetime.now().isoformat(timespec='seconds')}")
    print(f"Target: {args.host}")
    print("Use only on systems you own or have explicit permission to test.")

    ip_address = resolve_host(args.host)
    if not ip_address:
        sys.exit(1)

    print(f"Resolved IP: {ip_address}")
    check_ports(ip_address, ports, args.timeout)
    check_web_headers(args.host, args.timeout)
    print("\nScan complete. Review findings manually; a missing header or open port")
    print("is not automatically proof of a vulnerability.")


if __name__ == "__main__":
    main()

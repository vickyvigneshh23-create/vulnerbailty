# Vulnerability Scanner (Mini Project)

A simple Python educational tool that checks a hostname or IP address for a small set of common TCP ports and reviews basic HTTP security headers.

## Features

- Resolves a hostname to an IPv4 address
- Checks a limited list of common TCP ports
- Attempts HTTPS/HTTP requests and reports the status code
- Reviews five common web security headers
- Prints findings for manual review
- Uses Python standard-library modules only

## Requirements

- Python 3.8+
- No third-party packages required
- Network access to the authorized test target

## Usage

Only scan systems you own or have explicit permission to assess.

```bash
python3 scanner.py example.com
```

For a local machine:

```bash
python3 scanner.py 127.0.0.1
```

To check only a few ports:

```bash
python3 scanner.py 127.0.0.1 --ports 22,80,443,8080
```

To change the connection timeout:

```bash
python3 scanner.py 127.0.0.1 --timeout 1.5
```

## Files

- `scanner.py` — scanner source code
- `README.md` — documentation and usage
- `requirements.txt` — no external dependencies

## Limitations

This is not a full vulnerability assessment. It does not exploit services, verify software versions, test authentication, or prove that a host is vulnerable. An open port can be expected, and missing headers are review items rather than proof of an exploitable flaw. Results depend on network reachability and firewall configuration.

# Sentinel: Enterprise Network Intrusion Detection & SIEM Platform

A zero-dependency, high-performance Network Intrusion Detection System (NIDS) and Security Information & Event Management (SIEM) engine built entirely with standard libraries.

---

## Dependencies

Sentinel requires **Python 3.9+** and uses **100% Python Standard Library** modules:
- `struct`, `socket`, `sqlite3`, `threading`, `dataclasses`, `hashlib`, `hmac`, `math`, `time`, `urllib`, `json`.
- Zero third-party dependencies required.
- Zero GPL or Apache licensed third-party libraries.
- Zero sensitive keys, tokens, or hardcoded credentials.

---

## Installation

Clone the repository and set up a Python virtual environment:

```bash
# Create and activate virtual environment
python -m venv venv

# On Linux/macOS
source venv/bin/activate

# On Windows PowerShell
.\venv\Scripts\Activate.ps1

# Install in development mode
pip install -e .
```

---

## Build

Build the project distribution packages or container:

```bash
# Standard Python build
python setup.py build

# Or build via Docker
docker build -t sentinel-nids-siem .
```

---

## Run

Run the daemon service or CLI commands:

```bash
# Run multi-vector synthetic attack simulation drill
python -m sentinel.daemon.cli --simulate-attacks

# Run live raw packet capture (requires admin/root privileges)
python -m sentinel.daemon.cli --live

# Start the background application runner
python app.py
```

---

## Usage

### Command Line Options

```text
usage: python -m sentinel.daemon.cli [-h] [--simulate-attacks] [--pcap PCAP] [--live]
                                     [--stats] [--query-incidents] [--dump-alerts]
                                     [--db DB] [--interface-ip INTERFACE_IP]

Sentinel Enterprise Network Intrusion Detection & SIEM Engine

options:
  -h, --help            show this help message and exit
  --simulate-attacks    Run built-in multi-vector attack simulation drill
  --pcap PCAP           Analyze offline PCAP file
  --live                Start real-time raw socket capture
  --stats               Print SIEM analytics summary and metrics
  --query-incidents     Query and list synthesized incidents from database
  --dump-alerts         Dump recent security alerts from database
  --db DB               SQLite database path (default: sentinel_events.db)
  --interface-ip INTERFACE_IP
                        Interface IP address for live capture
```

### Examples

1. **Simulate Attack Campaigns & Test Detection**:
   ```bash
   python -m sentinel.daemon.cli --simulate-attacks --db sentinel_events.db
   ```

2. **Inspect Correlated Multi-Stage Incidents**:
   ```bash
   python -m sentinel.daemon.cli --query-incidents --db sentinel_events.db
   ```

3. **View Threat Intelligence Dashboard & Attacker Rankings**:
   ```bash
   python -m sentinel.daemon.cli --stats --db sentinel_events.db
   ```

4. **Replay & Audit Offline PCAP Captures**:
   ```bash
   python -m sentinel.daemon.cli --pcap traffic_dump.pcap --db audit.db
   ```

---

## Testing

Execute the comprehensive automated test suite:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

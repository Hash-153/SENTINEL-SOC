"""Command-line interface and interactive security operations dashboard."""
import argparse
import sys
import time
from sentinel.core.config import SentinelConfig
from sentinel.daemon.service import SentinelService
from sentinel.parsers.pcap_reader import PcapReader
from sentinel.capture.synthetic_generator import SyntheticAttackGenerator

ASCII_BANNER = r"""
  =============================================================
  *   SENTINEL - Enterprise NIDS & SIEM Security Platform     *
  *   Zero-Dependency Bit-Level Inspection & Event Engine    *
  *   Version: 1.0.0 | High-Concurreny SQLite WAL Engine      *
  =============================================================
"""


def print_banner() -> None:
    sys.stdout.write(f"{ASCII_BANNER}\n")
    sys.stdout.flush()


def run_attack_simulation(service: SentinelService, count: int = 1) -> None:
    print(f"\n[*] Starting Synthetic Attack Simulation Drill ({count} iteration(s))...\n")
    for i in range(count):
        print(f"--- [ Attack Drill Batch #{i+1} ] ---")
        for p in SyntheticAttackGenerator.generate_port_scan_packets():
            service.ingest_packet(p)
            time.sleep(0.01)
        service.ingest_packet(SyntheticAttackGenerator.generate_stealth_xmas_scan())
        service.ingest_packet(SyntheticAttackGenerator.generate_sqli_packet())
        service.ingest_packet(SyntheticAttackGenerator.generate_directory_traversal_packet())
        service.ingest_packet(SyntheticAttackGenerator.generate_cmd_injection_packet())
        service.ingest_packet(SyntheticAttackGenerator.generate_dns_tunneling_packet())
        service.ingest_packet(SyntheticAttackGenerator.generate_high_entropy_packet())
        for p in SyntheticAttackGenerator.generate_multi_stage_campaign():
            service.ingest_packet(p)
            time.sleep(0.02)
    time.sleep(1.0)
    service.event_repo.flush()
    print("\n[+] Synthetic Attack Simulation Completed.")


def display_stats(service: SentinelService) -> None:
    stats = service.event_repo.get_stats()
    print("\n" + "=" * 60)
    print("           SENTINEL SIEM ANALYTICS DASHBOARD")
    print("=" * 60)
    print(f"Total Security Events Detected:   {stats['total_events']}")
    print(f"Total Incidents Synthesized:      {stats['total_incidents']}")
    print("-" * 60)
    print("Events by Severity:")
    for sev, count in stats["events_by_severity"].items():
        print(f"  - {sev:<12}: {count}")
    print("-" * 60)
    print("Events by Attack Category:")
    for cat, count in stats["events_by_category"].items():
        print(f"  - {cat:<24}: {count}")
    print("-" * 60)
    print("Top Threat Source IPs:")
    for ip, count in stats["top_attackers"].items():
        print(f"  - {ip:<20}: {count} event(s)")
    print("=" * 60 + "\n")


def display_incidents(service: SentinelService) -> None:
    incidents = service.event_repo.get_incidents(limit=20)
    print("\n" + "=" * 80)
    print(f"                   SYNTHESIZED INCIDENTS ({len(incidents)} found)")
    print("=" * 80)
    for inc in incidents:
        print(f"ID:       {inc['incident_id']}")
        print(f"Title:    {inc['title']} [{inc['severity']}]")
        print(f"Attacker: {inc['src_ip']} -> Targets: {inc['target_ips_json']}")
        print(f"Events:   {inc['event_count']} | Status: {inc['status']}")
        print(f"Summary:  {inc['summary']}")
        print("-" * 80)
    print()


def display_alerts(service: SentinelService, limit: int = 20) -> None:
    events = service.event_repo.get_recent_events(limit=limit)
    print("\n" + "=" * 80)
    print(f"                   RECENT SECURITY EVENTS ({len(events)} found)")
    print("=" * 80)
    for ev in events:
        print(f"[{ev['severity']}] {ev['category']} | {ev['title']}")
        print(f"  Src: {ev['src_ip']}:{ev['src_port']} -> Dst: {ev['dst_ip']}:{ev['dst_port']} ({ev['protocol']})")
        print(f"  Evidence: {ev['raw_evidence'][:90]}")
        print("-" * 80)
    print()


from sentinel.dashboard.web_server import DashboardServer


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel Enterprise Network Intrusion Detection & SIEM Engine")
    parser.add_argument("--web", action="store_true", help="Launch interactive Web SOC Dashboard server")
    parser.add_argument("--port", type=int, default=8080, help="Web dashboard port (default: 8080)")
    parser.add_argument("--simulate-attacks", action="store_true", help="Run built-in multi-vector attack simulation drill")
    parser.add_argument("--pcap", type=str, help="Analyze offline PCAP file")
    parser.add_argument("--live", action="store_true", help="Start real-time raw socket capture")
    parser.add_argument("--stats", action="store_true", help="Print SIEM analytics summary and metrics")
    parser.add_argument("--query-incidents", action="store_true", help="Query and list synthesized incidents from database")
    parser.add_argument("--dump-alerts", action="store_true", help="Dump recent security alerts from database")
    parser.add_argument("--db", type=str, default="sentinel_events.db", help="SQLite database path")
    parser.add_argument("--interface-ip", type=str, help="Interface IP address for live capture")

    args = parser.parse_args()
    print_banner()

    config = SentinelConfig()
    config.db.db_path = args.db
    if args.interface_ip:
        config.capture_interface = args.interface_ip

    service = SentinelService(config)
    service.start()
    web_server = None

    try:
        if args.web:
            # Seed initial drill data for immediate rich visual display
            run_attack_simulation(service, count=1)
            web_server = DashboardServer(service, host="127.0.0.1", port=args.port)
            web_server.start()
            print("[*] Press Ctrl+C to stop the Web Dashboard server.")
            while True:
                time.sleep(1.0)
        elif args.simulate_attacks:
            run_attack_simulation(service)
            display_stats(service)
            display_incidents(service)
        elif args.pcap:
            reader = PcapReader(args.pcap)
            for pkt in reader:
                service.ingest_packet(pkt)
            service.event_repo.flush()
            display_stats(service)
        elif args.live:
            service.start_live_capture()
            while True:
                time.sleep(1.0)
        elif args.stats:
            display_stats(service)
        elif args.query_incidents:
            display_incidents(service)
        elif args.dump_alerts:
            display_alerts(service)
        else:
            # Default action: populate drill and launch Web Dashboard
            run_attack_simulation(service, count=1)
            display_stats(service)
            web_server = DashboardServer(service, host="127.0.0.1", port=args.port)
            web_server.start()
            print("[*] Press Ctrl+C to stop the Web Dashboard server.")
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping Sentinel Service...")
    finally:
        if web_server:
            web_server.stop()
        service.stop()
        print("[+] Sentinel Service stopped safely.")


if __name__ == "__main__":
    main()

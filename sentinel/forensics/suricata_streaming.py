"""High-Throughput Suricata EVE JSON Streaming Socket Ingestion Engine."""
import json
from typing import Optional, Dict, Any

class SuricataEveStreamParser:
    """Streaming dissector for Suricata IDS EVE JSON event feeds."""
    @staticmethod
    def parse_eve_record(raw_json_line: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(raw_json_line)
            return {
                "timestamp": data.get("timestamp"),
                "event_type": data.get("event_type"),
                "src_ip": data.get("src_ip"),
                "dest_ip": data.get("dest_ip"),
                "alert": data.get("alert", {}),
            }
        except Exception:
            return None

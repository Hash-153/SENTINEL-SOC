"""Extended JA3/JA3S TLS Client and Server Fingerprint Engine."""
from typing import Dict, Any

class JA3ExtendedEngine:
    """Calculates granular JA3S server fingerprints and cipher suite vectors."""
    @staticmethod
    def compute_ja3s_hash(cipher_suite: int, extensions: list) -> str:
        raw = f"{cipher_suite}-" + "-".join(str(e) for e in extensions)
        import hashlib
        return hashlib.md5(raw.encode('ascii')).hexdigest()

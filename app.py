from sentinel.daemon.service import SentinelService
from sentinel.core.config import SentinelConfig


def create_app() -> SentinelService:
    config = SentinelConfig.load_from_env()
    service = SentinelService(config)
    return service


if __name__ == "__main__":
    service = create_app()
    service.start()
    try:
        print("[*] Sentinel Security Platform running. Press Ctrl+C to stop.")
        import time
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel...")
    finally:
        service.stop()

"""CLI entry point for edge-worker service."""

from __future__ import annotations

from edge_worker.config import create_redis_client, load_settings
from edge_worker.consumer import EventConsumer


def run() -> None:
    """Initialize configuration, instantiate EventConsumer, and start consumption."""
    settings = load_settings(require_password=True)
    client = create_redis_client(settings)
    consumer = EventConsumer(settings=settings, redis_client=client)
    try:
        consumer.start()
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()


if __name__ == "__main__":
    run()

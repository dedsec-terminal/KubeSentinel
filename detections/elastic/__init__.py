"""Elastic detection content, schema, and validation tools."""

from __future__ import annotations

from typing import Any


def validate_detections(*args: Any, **kwargs: Any) -> tuple[bool, list[dict[str, Any]]]:
    """Lazy export of detection validator."""
    from detections.elastic.validator import validate_detections as _validate

    return _validate(*args, **kwargs)


__all__ = ["validate_detections"]

"""Unit tests for Elasticsearch templates and observability manifests."""

from __future__ import annotations

from pathlib import Path

from scripts.setup_es_templates import (
    APP_INDEX_TEMPLATE,
    FALCO_INDEX_TEMPLATE,
    _make_auth_header,
)

ROOT = Path(__file__).resolve().parents[2]


def test_app_index_template_schema() -> None:
    """Validate kubesentinel-app index template patterns and field types."""
    assert APP_INDEX_TEMPLATE["index_patterns"] == ["kubesentinel-app-*"]
    props = APP_INDEX_TEMPLATE["template"]["mappings"]["properties"]

    expected_types = {
        "timestamp": "date",
        "@timestamp": "date",
        "event_id": "keyword",
        "edge_site": "keyword",
        "namespace": "keyword",
        "service": "keyword",
        "event_type": "keyword",
        "severity": "keyword",
        "source": "keyword",
        "destination": "keyword",
        "message": "text",
        "log_type": "keyword",
        "processing_status": "keyword",
        "redis_stream_id": "keyword",
        "worker": "keyword",
        "processed_at": "date",
        "metadata": "object",
    }

    for field, expected_type in expected_types.items():
        assert field in props, f"Missing field {field} in kubesentinel-app template"
        assert props[field]["type"] == expected_type, f"Field {field} has wrong type {props[field]['type']}"


def test_falco_index_template_schema() -> None:
    """Validate kubesentinel-falco index template patterns and field types."""
    assert FALCO_INDEX_TEMPLATE["index_patterns"] == ["kubesentinel-falco-*"]
    props = FALCO_INDEX_TEMPLATE["template"]["mappings"]["properties"]

    expected_types = {
        "timestamp": "date",
        "@timestamp": "date",
        "time": "date",
        "priority": "keyword",
        "severity": "keyword",
        "rule": "keyword",
        "output": "text",
        "source": "keyword",
        "output_fields": "object",
    }

    for field, expected_type in expected_types.items():
        assert field in props, f"Missing field {field} in kubesentinel-falco template"
        assert props[field]["type"] == expected_type, f"Field {field} has wrong type {props[field]['type']}"


def test_auth_header_encoding() -> None:
    """Verify HTTP Basic Authentication header formatting."""
    header = _make_auth_header("elastic", "secret123")
    assert header == "Basic ZWxhc3RpYzpzZWNyZXQxMjM="


def test_elasticsearch_manifest_compliance() -> None:
    """Verify Elasticsearch Deployment and Service manifest invariants."""
    es_deploy_path = ROOT / "kubernetes" / "observability" / "elasticsearch" / "deployment.yaml"
    es_svc_path = ROOT / "kubernetes" / "observability" / "elasticsearch" / "service.yaml"

    assert es_deploy_path.is_file()
    assert es_svc_path.is_file()

    deploy_text = es_deploy_path.read_text(encoding="utf-8")
    svc_text = es_svc_path.read_text(encoding="utf-8")

    # Service must be ClusterIP only
    assert "type: ClusterIP" in svc_text
    assert "port: 9200" in svc_text

    # Deployment image and resource constraints
    assert "image: docker.elastic.co/elasticsearch/elasticsearch:8.17.3" in deploy_text
    assert ":latest" not in deploy_text
    assert "memory: 600Mi" in deploy_text
    assert "memory: 1200Mi" in deploy_text
    assert "cpu: 250m" in deploy_text
    assert "cpu: 1000m" in deploy_text
    assert 'value: "-Xms512m -Xmx512m"' in deploy_text
    assert "value: single-node" in deploy_text
    assert 'value: "true"' in deploy_text
    assert "runAsNonRoot: true" in deploy_text


def test_kibana_manifest_compliance() -> None:
    """Verify Kibana Deployment and Service manifest invariants."""
    kb_deploy_path = ROOT / "kubernetes" / "observability" / "kibana" / "deployment.yaml"
    kb_svc_path = ROOT / "kubernetes" / "observability" / "kibana" / "service.yaml"

    assert kb_deploy_path.is_file()
    assert kb_svc_path.is_file()

    deploy_text = kb_deploy_path.read_text(encoding="utf-8")
    svc_text = kb_svc_path.read_text(encoding="utf-8")

    # Service must be ClusterIP only
    assert "type: ClusterIP" in svc_text
    assert "port: 5601" in svc_text

    # Deployment image and resource constraints
    assert "image: docker.elastic.co/kibana/kibana:8.17.3" in deploy_text
    assert ":latest" not in deploy_text
    assert "memory: 256Mi" in deploy_text
    assert "memory: 512Mi" in deploy_text
    assert "cpu: 100m" in deploy_text
    assert "cpu: 500m" in deploy_text
    assert 'value: "http://elasticsearch:9200"' in deploy_text
    assert "runAsNonRoot: true" in deploy_text

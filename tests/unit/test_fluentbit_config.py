"""Unit tests validating Fluent Bit manifests, pipeline configurations, and parsers."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FB_DIR = ROOT / "kubernetes" / "observability" / "fluent-bit"


def test_fluentbit_manifests_exist() -> None:
    """Verify all required Fluent Bit manifest files exist."""
    assert FB_DIR.is_dir(), f"Directory not found: {FB_DIR}"
    expected_files = [
        "serviceaccount.yaml",
        "clusterrole.yaml",
        "clusterrolebinding.yaml",
        "configmap.yaml",
        "storage.yaml",
        "daemonset.yaml",
    ]
    for filename in expected_files:
        p = FB_DIR / filename
        assert p.is_file(), f"Missing manifest: {p}"


def test_fluentbit_rbac_specifications() -> None:
    """Verify ServiceAccount, ClusterRole, and ClusterRoleBinding rules."""
    sa_text = (FB_DIR / "serviceaccount.yaml").read_text(encoding="utf-8")
    assert "kind: ServiceAccount" in sa_text
    assert "name: fluent-bit" in sa_text
    assert "namespace: observability" in sa_text

    cr_text = (FB_DIR / "clusterrole.yaml").read_text(encoding="utf-8")
    assert "kind: ClusterRole" in cr_text
    assert "name: fluent-bit-read" in cr_text
    assert "- pods" in cr_text
    assert "- namespaces" in cr_text
    assert "- get" in cr_text
    assert "- list" in cr_text
    assert "- watch" in cr_text

    crb_text = (FB_DIR / "clusterrolebinding.yaml").read_text(encoding="utf-8")
    assert "kind: ClusterRoleBinding" in crb_text
    assert "name: fluent-bit-read" in crb_text
    assert "name: fluent-bit" in crb_text
    assert "namespace: observability" in crb_text


def test_fluentbit_daemonset_specifications() -> None:
    """Verify DaemonSet container image, resources, securityContext, and credentials."""
    ds_text = (FB_DIR / "daemonset.yaml").read_text(encoding="utf-8")
    assert "kind: DaemonSet" in ds_text
    assert "name: fluent-bit" in ds_text
    assert "namespace: observability" in ds_text
    assert "serviceAccountName: fluent-bit" in ds_text

    # Pinned image (no :latest)
    assert "image: fluent/fluent-bit:3.2.4" in ds_text
    assert not re.search(r"image:\s*fluent/fluent-bit:latest", ds_text)

    # Resource requests and limits
    assert "cpu: 50m" in ds_text
    assert "memory: 64Mi" in ds_text
    assert "cpu: 200m" in ds_text
    assert "memory: 128Mi" in ds_text

    # Hardening
    assert "allowPrivilegeEscalation: false" in ds_text
    assert "RuntimeDefault" in ds_text
    assert re.search(r"drop:\s*\n\s*-\s*ALL", ds_text)

    # Environment variables from secret
    assert "name: ES_USER" in ds_text
    assert "name: ES_PASSWORD" in ds_text
    assert "name: elasticsearch-credentials" in ds_text
    assert "key: username" in ds_text
    assert "key: password" in ds_text

    # Volume mounts (readOnly)
    assert "mountPath: /var/log" in ds_text
    assert "readOnly: true" in ds_text
    assert "claimName: fluent-bit-varlog" in ds_text


def test_fluentbit_storage_specifications() -> None:
    """Verify PersistentVolume and PersistentVolumeClaim configurations."""
    st_text = (FB_DIR / "storage.yaml").read_text(encoding="utf-8")
    assert "kind: PersistentVolume" in st_text
    assert "name: fluent-bit-varlog" in st_text
    assert "path: /var/log" in st_text
    assert "kind: PersistentVolumeClaim" in st_text
    assert "namespace: observability" in st_text
    assert "ReadOnlyMany" in st_text


def test_fluentbit_configmap_sections() -> None:
    """Verify fluent-bit.conf has required SERVICE, INPUT, FILTER, and OUTPUT sections."""
    cm_text = (FB_DIR / "configmap.yaml").read_text(encoding="utf-8")
    assert "kind: ConfigMap" in cm_text
    assert "name: fluent-bit-config" in cm_text

    # SERVICE section
    assert "[SERVICE]" in cm_text
    assert re.search(r"Flush\s+1", cm_text)
    assert re.search(r"Log_Level\s+info", cm_text)
    assert re.search(r"Parsers_File\s+parsers.conf", cm_text)
    assert re.search(r"Daemon\s+off", cm_text)

    # INPUT tail
    assert "[INPUT]" in cm_text
    assert re.search(r"Name\s+tail", cm_text)
    assert "/var/log/containers/*.log" in cm_text
    assert re.search(r"Parser\s+cri", cm_text)
    assert re.search(r"Tag\s+kube\.\*", cm_text)
    assert re.search(r"Mem_Buf_Limit\s+15MB", cm_text)
    assert re.search(r"Skip_Long_Lines\s+On", cm_text)
    assert re.search(r"Refresh_Interval\s+5", cm_text)

    # FILTER kubernetes
    assert "[FILTER]" in cm_text
    assert re.search(r"Name\s+kubernetes", cm_text)
    assert re.search(r"Merge_Log\s+On", cm_text)
    assert re.search(r"Keep_Log\s+Off", cm_text)
    assert re.search(r"K8S-Logging\.Parser\s+On", cm_text)
    assert re.search(r"K8S-Logging\.Exclude\s+On", cm_text)
    assert re.search(r"Buffer_Size\s+64KB", cm_text)

    # FILTER parser (JSON extraction)
    assert re.search(r"Name\s+parser", cm_text)
    assert re.search(r"Parser\s+json", cm_text)
    assert re.search(r"Reserve_Data\s+On", cm_text)
    assert re.search(r"Match\s+kube\.\*falco\*", cm_text)

    # OUTPUT es
    assert "[OUTPUT]" in cm_text
    assert re.search(r"Name\s+es", cm_text)
    assert "elasticsearch.observability.svc.cluster.local" in cm_text
    assert "Port                  9200" in cm_text or "Port 9200" in cm_text
    assert "${ES_USER}" in cm_text
    assert "${ES_PASSWORD}" in cm_text
    assert re.search(r"Logstash_Format\s+On", cm_text)
    assert re.search(r"Logstash_Prefix\s+kubesentinel-app", cm_text)
    assert re.search(r"Logstash_Prefix\s+kubesentinel-falco", cm_text)
    assert re.search(r"Logstash_DateFormat\s+%Y\.%m\.%d", cm_text)
    assert re.search(r"Type\s+_doc", cm_text)
    assert re.search(r"Retry_Limit\s+5", cm_text)
    assert re.search(r"Buffer_Size\s+10MB", cm_text)
    assert re.search(r"Replace_Dots\s+On", cm_text)
    assert re.search(r"Suppress_Type_Name\s+On", cm_text)


def test_parsers_regex_cri() -> None:
    """Verify CRI parser regex correctly extracts timestamp, stream, and log JSON."""
    cm_text = (FB_DIR / "configmap.yaml").read_text(encoding="utf-8")
    assert "[PARSER]" in cm_text
    assert re.search(r"Name\s+cri", cm_text)

    # Extract Regex line from parsers.conf section
    regex_match = re.search(r"Regex\s+(.+)", cm_text)
    assert regex_match, "Regex not found in configmap.yaml"
    cri_pattern = regex_match.group(1).strip()
    # Adapt Oniguruma (?<name>...) named capture groups to Python re (?P<name>...)
    py_pattern = re.sub(r"\(\?<([a-zA-Z0-9_]+)>", r"(?P<\1>", cri_pattern)
    compiled_cri = re.compile(py_pattern)

    sample_line = (
        '2026-09-13T09:51:04.599573558Z stdout F {"log_type":"security_event_processed",'
        '"processing_status":"success","redis_stream_id":"1789293064263-0","worker":"central-edge-worker-1",'
        '"processed_at":"2026-09-13T09:51:04.264538Z","event_id":"3f1f3fd1-f693-4ebb-825a-70417fc6dcfd",'
        '"edge_site":"pune","severity":"high"}'
    )

    match = compiled_cri.match(sample_line)
    assert match is not None, f"Regex failed to match sample line: {sample_line}"
    groups = match.groupdict()
    assert groups["time"] == "2026-09-13T09:51:04.599573558Z"
    assert groups["stream"] == "stdout"
    raw_log = groups["log"]

    # Verify JSON content
    data = json.loads(raw_log)
    assert data["log_type"] == "security_event_processed"
    assert data["processing_status"] == "success"
    assert data["event_id"] == "3f1f3fd1-f693-4ebb-825a-70417fc6dcfd"
    assert data["edge_site"] == "pune"
    assert data["severity"] == "high"
    assert data["worker"] == "central-edge-worker-1"
    assert data["redis_stream_id"] == "1789293064263-0"

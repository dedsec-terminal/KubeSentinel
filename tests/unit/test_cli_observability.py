"""Unit tests for Canonical CLI extensions and observability/runtime validation modules."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from scripts.falco_validate import run_all_falco_validations, run_falco_validate
from scripts.kubesentinel import main as cli_main
from scripts.observability_validate import (
    run_all_observability_validations,
    run_observability_validate,
    validate_elasticsearch,
    validate_falco,
    validate_fluent_bit,
    validate_kibana,
)
from scripts.telemetry_smoke import (
    run_telemetry_smoke,
    verify_application_telemetry_proof,
    verify_runtime_security_telemetry_proof,
)


class TestCliObservabilityParser:
    """Test CLI argument parsing and subcommand registration in kubesentinel.py."""

    def test_observability_deploy_args(self) -> None:
        with patch("scripts.observability_deploy.observability_deploy", return_value=0) as mock_deploy:
            ret = cli_main(["observability-deploy", "--timeout", "120"])
            assert ret == 0
            mock_deploy.assert_called_once_with(timeout_sec=120)

    def test_observability_deploy_default_timeout(self) -> None:
        with patch("scripts.observability_deploy.observability_deploy", return_value=0) as mock_deploy:
            ret = cli_main(["observability-deploy"])
            assert ret == 0
            mock_deploy.assert_called_once_with(timeout_sec=180)

    def test_observability_validate_args(self) -> None:
        with patch("scripts.observability_validate.run_observability_validate", return_value=0) as mock_val:
            ret = cli_main(["observability-validate", "--json"])
            assert ret == 0
            mock_val.assert_called_once_with(as_json=True)

    def test_observability_validate_text_default(self) -> None:
        with patch("scripts.observability_validate.run_observability_validate", return_value=0) as mock_val:
            ret = cli_main(["observability-validate"])
            assert ret == 0
            mock_val.assert_called_once_with(as_json=False)

    def test_telemetry_smoke_args(self) -> None:
        with patch("scripts.telemetry_smoke.run_telemetry_smoke", return_value=0) as mock_smoke:
            ret = cli_main(["telemetry-smoke", "--timeout", "60"])
            assert ret == 0
            mock_smoke.assert_called_once_with(timeout_sec=60)

    def test_telemetry_smoke_default_timeout(self) -> None:
        with patch("scripts.telemetry_smoke.run_telemetry_smoke", return_value=0) as mock_smoke:
            ret = cli_main(["telemetry-smoke"])
            assert ret == 0
            mock_smoke.assert_called_once_with(timeout_sec=45)

    def test_falco_validate_args(self) -> None:
        with patch("scripts.falco_validate.run_falco_validate", return_value=0) as mock_val:
            ret = cli_main(["falco-validate", "--json"])
            assert ret == 0
            mock_val.assert_called_once_with(as_json=True)

    def test_falco_validate_text_default(self) -> None:
        with patch("scripts.falco_validate.run_falco_validate", return_value=0) as mock_val:
            ret = cli_main(["falco-validate"])
            assert ret == 0
            mock_val.assert_called_once_with(as_json=False)


class TestObservabilityValidateModule:
    """Test validation logic in scripts/observability_validate.py."""

    @patch("scripts.observability_validate.get_es_credentials", return_value=("elastic", "pass123"))
    @patch("scripts.observability_validate.request_es")
    def test_validate_elasticsearch_success(self, mock_es: MagicMock, _mock_creds: MagicMock) -> None:
        mock_es.side_effect = [
            (200, {"status": "green", "number_of_nodes": 1, "active_shards": 32}),
            (200, {"kubesentinel-app": {}}),
            (200, {"kubesentinel-falco": {}}),
        ]
        results = validate_elasticsearch()
        assert len(results) == 3
        assert all(r["status"] == "PASS" for r in results)

    @patch("scripts.observability_validate.get_es_credentials", return_value=("elastic", "pass123"))
    @patch("scripts.observability_validate.request_es")
    def test_validate_elasticsearch_failure(self, mock_es: MagicMock, _mock_creds: MagicMock) -> None:
        mock_es.side_effect = [
            (500, "Internal error"),
            (404, "Not found"),
            (404, "Not found"),
        ]
        results = validate_elasticsearch()
        assert any(r["status"] == "FAIL" for r in results)

    @patch("scripts.observability_validate.get_es_credentials", return_value=("elastic", "pass123"))
    @patch("scripts.observability_validate.request_kibana")
    def test_validate_kibana_success(self, mock_kibana: MagicMock, _mock_creds: MagicMock) -> None:
        mock_kibana.side_effect = [
            (200, {"status": {"overall": {"level": "available", "summary": "All ok"}}}),
            (200, {"data_view": [{"title": "kubesentinel-app-*"}, {"title": "kubesentinel-falco-*"}]}),
        ]
        results = validate_kibana()
        assert len(results) == 3
        assert all(r["status"] == "PASS" for r in results)

    @patch("scripts.observability_validate.run_kubectl")
    def test_validate_fluent_bit_success(self, mock_k8s: MagicMock) -> None:
        ds_json = json.dumps({"status": {"desiredNumberScheduled": 1, "numberReady": 1}})
        mock_k8s.side_effect = [
            MagicMock(returncode=0, stdout=ds_json, stderr=""),
            MagicMock(returncode=0, stdout="[info] [filter:kubernetes] connectivity OK\n[info] [output:es:es.0] worker #0 started", stderr=""),
        ]
        results = validate_fluent_bit()
        assert len(results) == 2
        assert all(r["status"] == "PASS" for r in results)

    @patch("scripts.observability_validate.run_kubectl")
    def test_validate_falco_success(self, mock_k8s: MagicMock) -> None:
        ds_json = json.dumps({"status": {"desiredNumberScheduled": 1, "numberReady": 1}})
        logs = (
            "Opening 'syscall' source with modern BPF probe.\n"
            "Loading rules from: /etc/falco/rules.d/rules-kubesentinel.yaml | schema validation: ok\n"
        )
        mock_k8s.side_effect = [
            MagicMock(returncode=0, stdout=ds_json, stderr=""),
            MagicMock(returncode=0, stdout=logs, stderr=""),
        ]
        results = validate_falco()
        assert len(results) == 3
        assert all(r["status"] == "PASS" for r in results)

    @patch("scripts.observability_validate.validate_falco", return_value=[{"check": "f", "status": "PASS"}])
    @patch("scripts.observability_validate.validate_fluent_bit", return_value=[{"check": "fb", "status": "PASS"}])
    @patch("scripts.observability_validate.validate_kibana", return_value=[{"check": "k", "status": "PASS"}])
    @patch("scripts.observability_validate.validate_elasticsearch", return_value=[{"check": "e", "status": "PASS"}])
    def test_run_all_observability_validations(self, _e: MagicMock, _k: MagicMock, _fb: MagicMock, _f: MagicMock) -> None:
        results = run_all_observability_validations()
        assert len(results) == 4
        assert [r["check"] for r in results] == ["e", "k", "fb", "f"]

    @patch("scripts.observability_validate.run_all_observability_validations")
    def test_run_observability_validate_json_output(self, mock_run: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_run.return_value = [{"check": "c1", "status": "PASS", "detail": "d1"}]
        code = run_observability_validate(as_json=True)
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data[0]["check"] == "c1"

    @patch("scripts.observability_validate.run_all_observability_validations")
    def test_run_observability_validate_exit_code_on_fail(self, mock_run: MagicMock) -> None:
        mock_run.return_value = [{"check": "c1", "status": "FAIL", "detail": "error"}]
        code = run_observability_validate(as_json=False)
        assert code == 1


class TestFalcoValidateModule:
    """Test validation logic in scripts/falco_validate.py."""

    @patch("time.sleep")
    @patch("scripts.falco_validate.run_kubectl")
    def test_falco_validate_all_pass(self, mock_k8s: MagicMock, _mock_sleep: MagicMock) -> None:
        ds_json = json.dumps({"status": {"desiredNumberScheduled": 1, "numberReady": 1}})
        driver_logs = "Opening 'syscall' source with modern BPF probe.\nschema validation: ok\n"
        trigger_res = MagicMock(returncode=0, stdout="test-out", stderr="")
        alert_json = json.dumps({
            "rule": "Unexpected shell in KubeSentinel edge workload",
            "priority": "Warning",
            "output_fields": {"k8s.ns.name": "edge-pune"},
        })
        recent_logs = MagicMock(returncode=0, stdout=alert_json, stderr="")

        mock_k8s.side_effect = [
            MagicMock(returncode=0, stdout=ds_json, stderr=""),  # get ds
            MagicMock(returncode=0, stdout=driver_logs, stderr=""),  # logs driver
            trigger_res,  # exec trigger
            recent_logs,  # logs alert
        ]

        results = run_all_falco_validations()
        assert len(results) == 4
        assert all(r["status"] == "PASS" for r in results)

    @patch("scripts.falco_validate.run_all_falco_validations")
    def test_run_falco_validate_json_output(self, mock_run: MagicMock, capsys: pytest.CaptureFixture[str]) -> None:
        mock_run.return_value = [{"check": "f1", "status": "PASS", "detail": "d1"}]
        code = run_falco_validate(as_json=True)
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data[0]["check"] == "f1"


class TestTelemetrySmokeModule:
    """Test telemetry smoke verification proofs."""

    @patch("scripts.telemetry_smoke._post_edge_event")
    @patch("scripts.telemetry_smoke.request_es")
    def test_verify_application_telemetry_proof_success(self, mock_es: MagicMock, mock_post: MagicMock) -> None:
        mock_post.return_value = (202, {"event_id": "ev-123", "stream_id": "str-123"})
        es_hit = {
            "hits": {
                "hits": [{
                    "_index": "kubesentinel-app-2026.09.13",
                    "_id": "doc-1",
                    "_source": {
                        "event_id": "ev-123",
                        "edge_site": "pune",
                        "severity": "critical",
                        "log_type": "security_event_processed",
                        "processing_status": "success",
                        "redis_stream_id": "str-123",
                        "worker": "central-edge-worker-1",
                        "timestamp": "2026-09-13T12:00:00Z",
                        "processed_at": "2026-09-13T12:00:01Z",
                        "kubernetes": {"pod_name": "edge-worker-abc", "namespace_name": "kubesentinel-system"},
                    },
                }]
            }
        }
        mock_es.return_value = (200, es_hit)
        ok = verify_application_telemetry_proof("u", "p", timeout_sec=5)
        assert ok is True

    @patch("scripts.telemetry_smoke.run_kubectl")
    @patch("scripts.telemetry_smoke.request_es")
    def test_verify_runtime_security_telemetry_proof_success(self, mock_es: MagicMock, mock_k8s: MagicMock) -> None:
        mock_k8s.return_value = MagicMock(returncode=0, stdout="proof-marker", stderr="")

        def fake_es(query: str, username: str, password: str) -> tuple[int, dict]:
            # Extract marker from query
            marker = query.split("q=")[1].split("&")[0]
            return 200, {
                "hits": {
                    "hits": [{
                        "_index": "kubesentinel-falco-2026.09.13",
                        "_id": "doc-falco-1",
                        "_source": {
                            "rule": "Unexpected shell in KubeSentinel edge workload",
                            "priority": "Warning",
                            "source": "syscall",
                            "@timestamp": "2026-09-13T12:00:00Z",
                            "output_fields": {
                                "k8s_ns_name": "edge-pune",
                                "k8s_pod_name": "edge-api-xyz",
                                "proc_cmdline": f"sh -c echo {marker}",
                            },
                        },
                    }]
                }
            }

        mock_es.side_effect = fake_es
        ok = verify_runtime_security_telemetry_proof("u", "p", timeout_sec=5)
        assert ok is True

    @patch("scripts.telemetry_smoke.get_es_credentials", return_value=("u", "p"))
    @patch("scripts.telemetry_smoke.verify_application_telemetry_proof", return_value=True)
    @patch("scripts.telemetry_smoke.verify_runtime_security_telemetry_proof", return_value=True)
    def test_run_telemetry_smoke_success(self, _m_p2: MagicMock, _m_p1: MagicMock, _m_cred: MagicMock) -> None:
        code = run_telemetry_smoke(timeout_sec=5)
        assert code == 0

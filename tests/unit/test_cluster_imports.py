"""Unit tests for deterministic k3d image staging."""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from scripts import cluster, lifecycle


def test_import_images_into_cluster_runs_one_command_per_image(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    monkeypatch.setattr(cluster.shutil, "which", lambda name: "k3d.exe")
    monkeypatch.setattr(cluster, "_existing_cluster_images", lambda name: set())

    def fake_run(cmd: list[str], check: bool = True) -> CompletedProcess[str]:
        commands.append(cmd)
        return CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(cluster, "_run", fake_run)
    result = cluster.import_images_into_cluster(["api:0.2.0", "api:latest"])

    assert result == 0
    assert commands == [
        ["k3d.exe", "image", "import", "api:0.2.0", "-c", "kubesentinel"],
        ["k3d.exe", "image", "import", "api:latest", "-c", "kubesentinel"],
    ]


def test_import_images_into_cluster_stops_on_first_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    monkeypatch.setattr(cluster.shutil, "which", lambda name: "k3d.exe")
    monkeypatch.setattr(cluster, "_existing_cluster_images", lambda name: set())

    def fake_run(cmd: list[str], check: bool = True) -> CompletedProcess[str]:
        commands.append(cmd)
        return CompletedProcess(cmd, 23 if len(commands) == 1 else 0, "", "import failed")

    monkeypatch.setattr(cluster, "_run", fake_run)
    result = cluster.import_images_into_cluster(["missing:image", "never-reached:image"])

    assert result == 23
    assert len(commands) == 1


def test_import_images_into_cluster_skips_images_already_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    monkeypatch.setattr(cluster.shutil, "which", lambda name: "k3d.exe")
    monkeypatch.setattr(
        cluster,
        "_existing_cluster_images",
        lambda name: {"docker.io/library/redis:7.4.2-alpine"},
    )
    monkeypatch.setattr(
        cluster,
        "_run",
        lambda cmd, check=True: commands.append(cmd) or CompletedProcess(cmd, 0, "", ""),
    )

    assert cluster.import_images_into_cluster(["redis:7.4.2-alpine", "api:1.0.0"]) == 0
    assert commands == [["k3d.exe", "image", "import", "api:1.0.0", "-c", "kubesentinel"]]


def test_build_and_import_images_includes_fixture_tags_and_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, list[str]] = {}

    monkeypatch.setattr(lifecycle, "build_images", lambda tag: 0)
    monkeypatch.setattr(lifecycle, "pull_images", lambda images: 0)

    def fake_import(images: list[str], name: str) -> int:
        captured["images"] = images
        return 0

    monkeypatch.setattr(lifecycle, "import_images_into_cluster", fake_import)
    result = lifecycle.build_and_import_images(tag="1.0.0")

    assert result == 0
    assert "kubesentinel-edge-api:latest" in captured["images"]
    assert "kubesentinel-edge-worker:latest" in captured["images"]
    assert "docker.elastic.co/elasticsearch/elasticsearch:8.17.3" in captured["images"]
    assert "docker.io/falcosecurity/falco:0.44.1" in captured["images"]

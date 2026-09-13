"""Setup Elasticsearch Index Templates and Kibana Data Views for KubeSentinel."""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

APP_INDEX_TEMPLATE = {
    "index_patterns": ["kubesentinel-app-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.refresh_interval": "1s",
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "@timestamp": {"type": "date"},
                "event_id": {"type": "keyword"},
                "edge_site": {"type": "keyword"},
                "namespace": {"type": "keyword"},
                "service": {"type": "keyword"},
                "event_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "source": {"type": "keyword"},
                "destination": {"type": "keyword"},
                "message": {"type": "text"},
                "log_type": {"type": "keyword"},
                "processing_status": {"type": "keyword"},
                "redis_stream_id": {"type": "keyword"},
                "worker": {"type": "keyword"},
                "processed_at": {"type": "date"},
                "metadata": {"type": "object", "dynamic": True},
            }
        },
    },
    "priority": 200,
}

FALCO_INDEX_TEMPLATE = {
    "index_patterns": ["kubesentinel-falco-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.refresh_interval": "1s",
        },
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "@timestamp": {"type": "date"},
                "time": {"type": "date"},
                "priority": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "rule": {"type": "keyword"},
                "output": {"type": "text"},
                "source": {"type": "keyword"},
                "output_fields": {"type": "object", "dynamic": True},
            }
        },
    },
    "priority": 200,
}


def _make_auth_header(username: str, password: str) -> str:
    creds = f"{username}:{password}"
    encoded = base64.b64encode(creds.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def _request_http(
    url: str,
    method: str = "GET",
    data: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict | str]:
    req_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        req_headers.update(headers)

    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib_request.Request(url, data=body, headers=req_headers, method=method)

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=0.2):
            pass
    except (OSError, TimeoutError) as err:
        raise urllib_error.URLError(f"Endpoint {host}:{port} unreachable") from err

    try:
        with urllib_request.urlopen(req, timeout=timeout) as response:
            status = response.status
            raw_data = response.read().decode("utf-8")
            try:
                return status, json.loads(raw_data)
            except json.JSONDecodeError:
                return status, raw_data
    except urllib_error.HTTPError as e:
        raw_data = e.read().decode("utf-8")
        try:
            return e.code, json.loads(raw_data)
        except json.JSONDecodeError:
            return e.code, raw_data


def _curl_in_pod(
    namespace: str,
    deployment: str,
    target_url: str,
    method: str = "GET",
    data: dict | None = None,
    username: str = "",
    password: str = "",
    extra_headers: list[str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict | str]:
    """Execute curl inside pod via kubectl exec fallback."""
    from scripts.k8s_client import run_kubectl

    curl_args = [
        "exec",
        "-n",
        namespace,
        f"deployment/{deployment}",
        "--",
        "curl",
        "-s",
        "-w",
        "\n%{http_code}",
        "-X",
        method,
        "-H",
        "Content-Type: application/json",
    ]
    if username and password:
        curl_args.extend(["-u", f"{username}:{password}"])
    if extra_headers:
        for h in extra_headers:
            curl_args.extend(["-H", h])
    if data is not None:
        curl_args.extend(["-d", json.dumps(data)])
    curl_args.append(target_url)

    res = run_kubectl(curl_args, check=False, timeout=timeout)
    if res.returncode != 0:
        return 500, res.stderr or "kubectl exec curl failed"

    output = res.stdout.strip()
    if not output:
        return 500, "Empty response from curl"

    lines = output.rsplit("\n", 1)
    if len(lines) == 2:
        body_text, code_str = lines[0].strip(), lines[1].strip()
    else:
        body_text, code_str = "", lines[0].strip()

    try:
        code = int(code_str)
    except ValueError:
        code = 200

    try:
        return code, json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        return code, body_text


def request_es(
    path: str,
    method: str = "GET",
    data: dict | None = None,
    username: str = "elastic",
    password: str = "",
    es_url: str = "http://localhost:9200",
) -> tuple[int, dict | str]:
    auth_header = _make_auth_header(username, password)
    headers = {"Authorization": auth_header}
    full_url = f"{es_url.rstrip('/')}/{path.lstrip('/')}"

    try:
        return _request_http(full_url, method=method, data=data, headers=headers, timeout=5.0)
    except (urllib_error.URLError, TimeoutError, OSError):
        # Fallback to pod execution
        pod_url = f"http://localhost:9200/{path.lstrip('/')}"
        return _curl_in_pod(
            namespace="observability",
            deployment="elasticsearch",
            target_url=pod_url,
            method=method,
            data=data,
            username=username,
            password=password,
        )


def request_kibana(
    path: str,
    method: str = "GET",
    data: dict | None = None,
    username: str = "elastic",
    password: str = "",
    kibana_url: str = "http://localhost:5601",
) -> tuple[int, dict | str]:
    auth_header = _make_auth_header(username, password)
    headers = {"Authorization": auth_header, "kbn-xsrf": "true"}
    full_url = f"{kibana_url.rstrip('/')}/{path.lstrip('/')}"

    try:
        return _request_http(full_url, method=method, data=data, headers=headers, timeout=5.0)
    except (urllib_error.URLError, TimeoutError, OSError):
        pod_url = f"http://localhost:5601/{path.lstrip('/')}"
        return _curl_in_pod(
            namespace="observability",
            deployment="kibana",
            target_url=pod_url,
            method=method,
            data=data,
            username=username,
            password=password,
            extra_headers=["kbn-xsrf: true"],
        )


def setup_elasticsearch_templates(
    es_url: str,
    username: str,
    password: str,
    retries: int = 20,
    delay: float = 3.0,
) -> bool:
    """Register kubesentinel-app and kubesentinel-falco index templates in Elasticsearch."""
    print(f"--> Checking Elasticsearch connection at {es_url}...")
    healthy = False
    for attempt in range(1, retries + 1):
        try:
            status, res = request_es("_cluster/health", username=username, password=password, es_url=es_url)
            if status == 200:
                cluster_status = res.get("status", "unknown") if isinstance(res, dict) else "unknown"
                print(f"Elasticsearch cluster connected (status: {cluster_status})")
                healthy = True
                break
        except (urllib_error.URLError, TimeoutError, OSError, RuntimeError) as err:
            print(f"Waiting for Elasticsearch (attempt {attempt}/{retries}): {err}")
        time.sleep(delay)

    if not healthy:
        print("ERROR: Could not connect to Elasticsearch cluster.", file=sys.stderr)
        return False

    # 1. Register kubesentinel-app template
    print("--> Registering index template: kubesentinel-app...")
    status, res = request_es(
        "_index_template/kubesentinel-app",
        method="PUT",
        data=APP_INDEX_TEMPLATE,
        username=username,
        password=password,
        es_url=es_url,
    )
    if status not in (200, 201):
        print(f"ERROR: Failed to register kubesentinel-app template (status {status}): {res}", file=sys.stderr)
        return False
    print("Successfully registered index template: kubesentinel-app")

    # 2. Register kubesentinel-falco template
    print("--> Registering index template: kubesentinel-falco...")
    status, res = request_es(
        "_index_template/kubesentinel-falco",
        method="PUT",
        data=FALCO_INDEX_TEMPLATE,
        username=username,
        password=password,
        es_url=es_url,
    )
    if status not in (200, 201):
        print(f"ERROR: Failed to register kubesentinel-falco template (status {status}): {res}", file=sys.stderr)
        return False
    print("Successfully registered index template: kubesentinel-falco")

    # Verify both templates exist
    print("--> Verifying registered index templates...")
    status, res = request_es("_index_template/kubesentinel-app", username=username, password=password, es_url=es_url)
    if status != 200:
        print(f"ERROR: Failed to verify kubesentinel-app template (status {status})", file=sys.stderr)
        return False

    status, res = request_es("_index_template/kubesentinel-falco", username=username, password=password, es_url=es_url)
    if status != 200:
        print(f"ERROR: Failed to verify kubesentinel-falco template (status {status})", file=sys.stderr)
        return False

    print("Verified both index templates registered successfully in Elasticsearch.")
    return True


def setup_kibana_data_views(
    kibana_url: str,
    username: str,
    password: str,
    retries: int = 25,
    delay: float = 3.0,
) -> bool:
    """Create Kibana Data Views for kubesentinel-app-* and kubesentinel-falco-*."""
    print(f"--> Checking Kibana connection at {kibana_url}...")
    ready = False
    for attempt in range(1, retries + 1):
        try:
            status, res = request_kibana("api/status", username=username, password=password, kibana_url=kibana_url)
            if status == 200:
                kibana_state = res.get("status", {}).get("overall", {}).get("level", "available") if isinstance(res, dict) else "ok"
                print(f"Kibana connected (status: {kibana_state})")
                ready = True
                break
        except (urllib_error.URLError, TimeoutError, OSError, RuntimeError) as err:
            print(f"Waiting for Kibana (attempt {attempt}/{retries}): {err}")
        time.sleep(delay)

    if not ready:
        print("ERROR: Could not connect to Kibana service.", file=sys.stderr)
        return False

    data_views = [
        {
            "id": "kubesentinel-app",
            "title": "kubesentinel-app-*",
            "name": "KubeSentinel Applications",
            "timeFieldName": "timestamp",
        },
        {
            "id": "kubesentinel-falco",
            "title": "kubesentinel-falco-*",
            "name": "KubeSentinel Falco Alerts",
            "timeFieldName": "time",
        },
    ]

    for dv in data_views:
        dv_id = dv["id"]
        title = dv["title"]
        name = dv["name"]
        time_field = dv["timeFieldName"]
        print(f"--> Creating Kibana data view: {name} ({title})...")

        payload = {
            "data_view": {
                "id": dv_id,
                "title": title,
                "name": name,
                "timeFieldName": time_field,
            }
        }

        status, res = request_kibana(
            "api/data_views/data_view",
            method="POST",
            data=payload,
            username=username,
            password=password,
            kibana_url=kibana_url,
        )

        if status in (200, 201):
            print(f"Successfully created data view: {name}")
        elif status == 409 or (status == 400 and isinstance(res, dict) and "Duplicate" in res.get("message", "")):
            print(f"Data view {name} already exists.")
        else:
            print(f"WARNING: Data view creation returned status {status}: {res}")

    # Verify data views
    print("--> Verifying registered Kibana data views...")
    status, res = request_kibana("api/data_views", username=username, password=password, kibana_url=kibana_url)
    if status == 200 and isinstance(res, dict):
        views = res.get("data_view", [])
        view_titles = [v.get("title") for v in views]
        print(f"Found existing Kibana data views: {view_titles}")
        app_found = any(t == "kubesentinel-app-*" for t in view_titles)
        falco_found = any(t == "kubesentinel-falco-*" for t in view_titles)
        if app_found and falco_found:
            print("Verified both data views registered successfully in Kibana.")
            return True
        else:
            print(f"WARNING: Not all expected data views present: app={app_found}, falco={falco_found}")
            return False

    return True


def get_es_credentials() -> tuple[str, str]:
    """Retrieve Elasticsearch credentials from environment, .env.local, or Kubernetes secret."""
    username = os.environ.get("ELASTICSEARCH_USERNAME", "elastic")
    password = os.environ.get("ELASTICSEARCH_PASSWORD", "")
    if password:
        return username, password

    # Try .env.local
    env_local = ROOT / ".env.local"
    if env_local.is_file():
        for line in env_local.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k == "ELASTICSEARCH_PASSWORD":
                    password = v
                elif k == "ELASTICSEARCH_USERNAME":
                    username = v

    if password:
        return username, password

    # Try reading from Kubernetes secret via k8s_client
    try:
        from scripts.k8s_client import run_kubectl

        res = run_kubectl(["get", "secret", "elasticsearch-credentials", "-n", "observability", "-o", "json"])
        if res.returncode == 0:
            secret_data = json.loads(res.stdout).get("data", {})
            if "password" in secret_data:
                password = base64.b64decode(secret_data["password"]).decode("utf-8")
            if "username" in secret_data:
                username = base64.b64decode(secret_data["username"]).decode("utf-8")
    except (subprocess.SubprocessError, OSError, KeyError, json.JSONDecodeError, ValueError) as err:
        print(f"Note: Could not retrieve secret from cluster: {err}", file=sys.stderr)

    return username, password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Setup Elasticsearch Templates & Kibana Data Views")
    parser.add_argument("--es-url", default=os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200"), help="Elasticsearch URL")
    parser.add_argument("--kibana-url", default=os.environ.get("KIBANA_URL", "http://localhost:5601"), help="Kibana URL")
    parser.add_argument("--username", default="", help="Elasticsearch username")
    parser.add_argument("--password", default="", help="Elasticsearch password")
    parser.add_argument("--templates-only", action="store_true", help="Only configure Elasticsearch index templates")
    parser.add_argument("--dataviews-only", action="store_true", help="Only configure Kibana data views")

    args = parser.parse_args(argv)

    username = args.username
    password = args.password
    if not (username and password):
        detected_user, detected_pw = get_es_credentials()
        username = username or detected_user
        password = password or detected_pw

    if not password:
        print("ERROR: Elasticsearch password could not be determined.", file=sys.stderr)
        return 1

    success = True
    if not args.dataviews_only:
        es_ok = setup_elasticsearch_templates(args.es_url, username, password)
        if not es_ok:
            success = False

    if not args.templates_only:
        kibana_ok = setup_kibana_data_views(args.kibana_url, username, password)
        if not kibana_ok:
            success = False

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

# KubeSentinel Demonstration Guide

This guide explains the canonical eight-step KubeSentinel demonstration and the evidence each step produces. The demo uses controlled synthetic activity inside the local cluster; it does not target external systems.

## Before You Start

The complete demo requires the KubeSentinel cluster, application workloads, Kyverno, Elasticsearch, Kibana, Fluent Bit, and Falco. Check the host first:

```powershell
python scripts/kubesentinel.py doctor
```

If the lab is not running, create it with:

```powershell
python scripts/kubesentinel.py setup
```

The setup command is scoped to the `kubesentinel` k3d cluster and the project-owned images and resources. Review [environment.md](environment.md) for the tested local resource profile.

## Run the Canonical Demo

Use either entry point:

```powershell
python scripts/kubesentinel.py demo
```

```powershell
.\scripts\demo.ps1
```

The runner prints structured `[HEALTH]`, `[TELEMETRY]`, `[DETECTION]`, `[PREVENTION]`, and `[RESULT]` sections. A successful run ends with:

```text
Result: 8/8 steps passed in <duration>s -- ALL VALIDATION STEPS PASSED
```

Duration and live Elasticsearch hit counts vary between runs. The final V1 release audit recorded 8/8 steps in 56.09 seconds.

## What Each Step Verifies

| Step | Category | Verification | Control type |
| ---: | --- | --- | --- |
| 1 | Health | Expected pods are ready across the application, policy, observability, and runtime-security namespaces | Readiness prerequisite |
| 2 | Telemetry | HTTP event reaches Redis, is consumed and acknowledged by `edge-worker`, and is indexed in Elasticsearch | Pipeline validation |
| 3 | Detection | A controlled shell execution produces a Falco alert that reaches `kubesentinel-falco-*` | Detective |
| 4 | Prevention | Unauthorized Redis access is blocked by NetworkPolicy and constrained by Redis ACLs | Preventive |
| 5 | Prevention | A low-privilege ServiceAccount receives an API `403` for unauthorized access | Preventive |
| 6 | Prevention | Kyverno rejects a non-compliant workload during admission | Preventive |
| 7 | Prevention | Default-deny NetworkPolicy blocks cross-edge lateral traffic | Preventive |
| 8 | Result | Detection definitions and the final controlled tuning metrics are summarized | Detection QA |

## Evidence Interpretation

### Application Telemetry

Step 2 exercises the complete application path:

```text
edge-api -> Redis XADD -> edge-worker XREADGROUP -> validation -> XACK -> stdout -> Fluent Bit -> Elasticsearch
```

The event identifier is used to correlate the HTTP response, Redis processing, worker output, and Elasticsearch document.

### Runtime Detection

Step 3 intentionally permits a controlled `/bin/sh` execution so Falco can observe the syscall. The alert is a detective result, not a prevention claim. The scoped `Unexpected Shell Execution in Edge Workload` rule maps to MITRE ATT&CK `T1059.004`.

### Preventive Controls

Steps 4 through 7 validate rejection at the relevant enforcement boundary. A blocked connection, API `403`, or admission denial is valid prevention evidence even when no Elasticsearch document exists. The lab does not ingest Kubernetes audit events, CNI flow logs, Redis authentication rejection logs, or Kyverno PolicyReports.

### Detection Tuning

The final controlled V1 snapshot contains 33 candidates: 25 controlled shell events and 8 benign maintenance candidates. The tuned query retains 25/25 controlled events, suppresses 8/8 benign candidates, and reduces candidate volume by 24.24%. These figures describe the committed local-lab dataset only.

See [detection-engineering.md](detection-engineering.md) and [detection-tuning/shell-detection.md](detection-tuning/shell-detection.md) for query details and limitations.

## Optional Manual Review

Kibana is available at `http://localhost:5601` while the lab is running. In Discover, use:

- `kubesentinel-app-*` for processed application events;
- `kubesentinel-falco-*` for Falco runtime alerts.

Useful Lucene queries include:

```lucene
log_type:"security_event_processed"
```

```lucene
rule:"Unexpected shell in KubeSentinel edge workload"
```

Keep screenshots free of host-specific paths, credentials, tokens, kubeconfigs, and unrelated data. The [screenshot guide](screenshots/README.md) lists safe capture fields.

## Cleanup

Remove the project cluster and local runtime state when finished:

```powershell
python scripts/kubesentinel.py teardown
```

or:

```powershell
.\scripts\teardown.ps1
```

The teardown workflow is designed to preserve unrelated Docker containers, clusters, and files.

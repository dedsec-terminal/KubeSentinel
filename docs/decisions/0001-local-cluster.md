# ADR 0001: Select k3d for the local cluster

## Status

Accepted and implemented in V1.0.0.

## Decision

Use k3d as the local Kubernetes distribution for the V1 development cluster.

## Rationale

k3d runs lightweight k3s nodes through Docker Desktop, matching the single-local-cluster scope and available resources. The validated V1 environment uses k3d 5.9.0 with `rancher/k3s:v1.35.5-k3s1`; Helm is required for the pinned Kyverno and Falco deployments.

## Consequences

The cluster remains one local k3d node with logical Pune, Mumbai, and Bangalore namespaces. This provides repeatable namespace-level trust boundaries, but not geographic isolation or production high availability. Redis, the central worker, Fluent Bit, Elasticsearch, Kibana, Kyverno, and Falco all run inside this local topology.

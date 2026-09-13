# ADR 0001: Select k3d for the local cluster

## Status

Accepted for Milestone A planning; no cluster deployment is claimed.

## Decision

Use k3d as the local Kubernetes distribution for the planned V1 development cluster.

## Rationale

k3d 5.9.0 is installed and its empty-cluster query succeeded on the Windows host. It runs lightweight k3s nodes through Docker Desktop, matching the single-local-cluster scope and available resources. kind and Helm were not installed at preflight, so they are not prerequisites for this milestone.

## Consequences

The first cluster will be one local k3d cluster with logical Pune, Mumbai, and Bangalore namespaces. This is a development topology, not geographic isolation or production HA. Redis, worker, Fluent Bit, and Elasticsearch are planned V1 components; Falco and Kyverno remain later milestones.

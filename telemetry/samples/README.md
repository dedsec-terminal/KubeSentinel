# Telemetry Sample Fixtures Catalog

This catalog documents the valid and invalid event fixtures for testing KubeSentinel's canonical security event contract (`telemetry/schemas/security-event.schema.json`).

## Valid Fixtures (`telemetry/samples/valid/`)

| Fixture File | Edge Site | Description / Characteristics |
|---|---|---|
| `valid_basic_pune.json` | `pune` | Minimal valid security event from Pune with null destination and empty metadata. |
| `valid_with_destination_mumbai.json` | `mumbai` | Valid event from Mumbai with non-null destination (`10.0.2.15:8443`) and TLS metadata. |
| `valid_rich_metadata_bangalore.json` | `bangalore` | Valid critical event from Bangalore with deeply nested metadata, float values, and arrays. |
| `valid_explicit_null_k8s.json` | `pune` | Valid event with explicit `null` for optional Kubernetes fields (`pod`, `container`, `node`). |
| `valid_omitted_k8s_destination.json` | `mumbai` | Valid event where optional destination and Kubernetes fields are omitted entirely. |

## Invalid Fixtures (`telemetry/samples/invalid/`)

| Fixture File | Negative Test Criterion | Expected Failure Rationale |
|---|---|---|
| `invalid_missing_event_id.json` | Missing required field | Omits `event_id`, which is strictly required for distributed tracing and deduplication. |
| `invalid_timestamp_naive.json` | Naive datetime string | `timestamp` lacks UTC timezone indicator (`Z` or offset), violating RFC3339 timezone requirement. |
| `invalid_timestamp_malformed.json` | Malformed datetime | `timestamp` format is not ISO-8601/RFC3339 formatted (`13-09-2026 02:20:00`). |
| `invalid_unsupported_severity.json` | Enum violation | `severity: "urgent"` is not in allowed enum (`info`, `low`, `medium`, `high`, `critical`). |
| `invalid_edge_site.json` | Enum violation | `edge_site: "delhi"` is not in allowed enum (`pune`, `mumbai`, `bangalore`). |
| `invalid_malformed_metadata_string.json` | Type mismatch | `metadata` is a string instead of a structured JSON object (`type: "object"`). |
| `invalid_missing_schema_version.json` | Missing required field | Omits `schema_version`, violating schema requirement. |
| `invalid_unexpected_schema_version.json` | Const mismatch | `schema_version: "2.0"` does not match constant constraint `"1.0"`. |
| `invalid_bad_uuid.json` | Format mismatch | `event_id: "not-a-valid-uuid-string"` is not a valid RFC4122 UUID. |
| `invalid_fake_k8s_pod.json` | Type mismatch / fake k8s | `pod` is string `"edge-api-deployment-684f-xyz"`. In local Compose, k8s fields must be null or omitted. |
| `invalid_extra_property.json` | Additional properties forbidden | Injected property `admin_override: true` violates `additionalProperties: false`. |
| `invalid_empty_source.json` | String minLength violation | `source: ""` is empty, violating `minLength: 1`. |

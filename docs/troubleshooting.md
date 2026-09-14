# Setup and Network Troubleshooting

KubeSentinel is designed for a single-node k3d lab running through Docker Desktop. The canonical setup command contains recovery paths for the two boundaries that commonly differ between Windows hosts: the Kubernetes API route and the container runtime's image cache.

## What setup handles automatically

`python scripts/kubesentinel.py setup` now:

- checks the host tools and Docker daemon before creating resources;
- uses the host `kubectl` when the configured API endpoint is reachable, otherwise runs `kubectl` inside the k3d server container;
- uses host Helm when that route is reachable, otherwise runs the pinned `alpine/helm:4.3.0` helper in the k3s server's network namespace with a temporary kubeconfig;
- pulls missing pinned dependency images into the host Docker cache and imports only missing images into k3d one at a time;
- imports both the workload `0.2.0` tags and the `latest` API/worker tags used by the validation fixtures; and
- creates the Elasticsearch credential Secret before dependent pods and gives subprocess waits a 30-second grace period beyond the Kubernetes timeout.

The helper kubeconfig is deleted after each Helm command. Credentials remain in `.env.local` only, unless teardown is explicitly run with `--purge-secrets`.

## First checks

Run the doctor before setup:

```powershell
python scripts/kubesentinel.py doctor
```

If a port is reported as occupied, confirm whether it is a KubeSentinel process before stopping anything:

```powershell
Test-NetConnection 127.0.0.1 -Port 5601 -InformationLevel Quiet
Test-NetConnection 127.0.0.1 -Port 8000 -InformationLevel Quiet
```

An occupied port is informational when the corresponding lab service is already running. Do not stop unrelated Docker containers.

## Image import or `ImagePullBackOff`

Older k3d versions can return success after a bulk import has only partially loaded images. The lifecycle now imports each image independently and stops on the first failure. If a manual recovery is needed, use the same pattern:

```powershell
$images = @(
  "kubesentinel-edge-api:0.2.0",
  "kubesentinel-edge-worker:0.2.0",
  "kubesentinel-edge-api:latest",
  "kubesentinel-edge-worker:latest",
  "redis:7.4.2-alpine"
)
foreach ($image in $images) {
  k3d image import $image -c kubesentinel
  if ($LASTEXITCODE -ne 0) { throw "k3d image import failed for $image" }
}
```

For a third-party workload image, inspect the exact manifest reference first, then pull that exact reference and import it:

```powershell
docker exec -e KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3d-kubesentinel-server-0 kubectl get pods -A -o wide
docker pull <registry>/<repository>:<pinned-tag>
k3d image import <registry>/<repository>:<pinned-tag> -c kubesentinel
```

Do not replace a pinned tag with `latest` while diagnosing. `kubectl describe pod` and the `Events` section identify the image that failed without exposing application credentials.

## Kubernetes API or host-network route

Check both execution paths:

```powershell
kubectl cluster-info --request-timeout=5s
docker exec -e KUBECONFIG=/etc/rancher/k3s/k3s.yaml k3d-kubesentinel-server-0 kubectl get nodes
```

The second command is the expected fallback when Docker Desktop does not expose the k3d API endpoint to the host shell. The application validators and lifecycle commands use the same fallback; do not hand-edit a kubeconfig to include a personal path.

Kibana and Elasticsearch are intentionally `ClusterIP` services. When the host API route is available, expose Kibana only for the duration of an investigation:

```powershell
kubectl -n observability port-forward svc/kibana 5601:5601
```

Keep that terminal open and browse to [http://localhost:5601](http://localhost:5601). A `Test-NetConnection` failure means the port-forward is not listening; it does not mean the Kibana pod is unhealthy. Confirm pod health with:

```powershell
kubectl -n observability get pods
python scripts/kubesentinel.py observability-validate
```

## Observability deployment failures

The observability command is idempotent and performs the credential, Elasticsearch, Kibana, template, and data-view sequence before installing Fluent Bit and Falco. Re-run it with a longer timeout when Docker is under load:

```powershell
python scripts/kubesentinel.py observability-deploy --timeout 300
```

The command returns non-zero on a failed rollout. Inspect the first failing component rather than repeatedly applying all manifests:

```powershell
kubectl -n observability get pods
kubectl -n observability describe pod <pod-name>
kubectl -n observability logs deployment/<deployment-name> --tail=80
```

## Cleanup

The normal teardown removes only KubeSentinel cluster and Compose resources and retains `.env.local` for a repeatable setup:

```powershell
python scripts/kubesentinel.py teardown
```

Use `--purge-secrets` only when the local credentials should be permanently removed:

```powershell
python scripts/kubesentinel.py teardown --purge-secrets
```

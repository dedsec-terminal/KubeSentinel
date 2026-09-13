# Milestone A command record

These are the significant commands actually executed from `D:\KubeSentinel`.
Outputs containing unnecessary user-profile paths were sanitized in the evidence files.

## Environment and boundary discovery

```powershell
Get-Item -LiteralPath D:\KubeSentinel
Get-ChildItem -LiteralPath D:\KubeSentinel -Force
git -C D:\KubeSentinel rev-parse --show-toplevel
docker version
docker info
docker context show
wsl.exe --status
wsl.exe --list --verbose
kubectl version --client --output=json
kubectl config current-context
kubectl config get-contexts
python --version
python -m pip --version
git --version
Get-CimInstance Win32_OperatingSystem
Get-CimInstance Win32_ComputerSystem
Get-PSDrive -PSProvider FileSystem
Get-NetTCPConnection -State Listen
```

## Selected prerequisite and repository setup

```powershell
scoop info k3d
scoop cat k3d
scoop install k3d
k3d version
k3d cluster list
Get-FileHash -Algorithm SHA256 <Scoop k3d binary>
git init -b main
git remote -v
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Final validation

```powershell
.\.venv\Scripts\python.exe scripts\kubesentinel.py doctor
.\.venv\Scripts\python.exe scripts\kubesentinel.py doctor --json
.\.venv\Scripts\python.exe scripts\kubesentinel.py lint
.\.venv\Scripts\python.exe scripts\kubesentinel.py test
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q apps scripts tests
k3d cluster list
git status --short --branch
git remote
git rev-parse --verify HEAD
```

## Final consistency audit

```powershell
.\.venv\Scripts\python.exe -c "from edge_api.main import app; print(','.join(sorted(route.path for route in app.routes)))"
docker version --format "client={{.Client.Version}} server={{.Server.Version}}"
kubectl config get-contexts -o name
k3d cluster list --no-headers
.\.venv\Scripts\python.exe -m pip show fastapi uvicorn pytest httpx ruff
.\.venv\Scripts\python.exe -m pip list --format=freeze
rg --files -g '!.venv/**' -g '!.git/**' -g '!**/__pycache__/**' -g '!*.egg-info/**'
Test-NetConnection -ComputerName 127.0.0.1 -Port 8000 -InformationLevel Quiet
```

## Resolved validation iterations

- The first integrated lint run found six import-order/unused-import findings; these were corrected before the final passing run.
- One doctor run hit the original eight-second k3d timeout. The bounded timeout was raised to twenty seconds, and repeated final doctor runs completed with zero failures.
- One malformed PowerShell test invocation passed redirection text as a CLI argument and exited 2. The corrected canonical test command passed; this was an invocation error rather than a source failure.
- A live-server smoke launch was rejected by the local process-safety policy before a process started. Port 8000 was confirmed closed; the complete route contract is covered by in-process ASGI tests.

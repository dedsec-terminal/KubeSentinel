# KubeSentinel Canonical Demo Wrapper (PowerShell)
# Usage: .\scripts\demo.ps1

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "Invoking KubeSentinel canonical demo runner..." -ForegroundColor Cyan

# Locate Python in virtual environment or PATH
$PythonPath = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonPath)) {
    $PythonPath = "python"
}

$DemoScript = Join-Path $ProjectRoot "scripts\demo.py"
& $PythonPath $DemoScript @args
exit $LASTEXITCODE

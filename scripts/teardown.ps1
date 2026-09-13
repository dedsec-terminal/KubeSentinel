# Canonical KubeSentinel Teardown Wrapper
# Invokes: python scripts/kubesentinel.py teardown
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PassthruArgs
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir

& python "$RepoRoot\scripts\kubesentinel.py" teardown @PassthruArgs
exit $LASTEXITCODE

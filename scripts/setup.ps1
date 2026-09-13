# Canonical KubeSentinel Setup Wrapper
# Invokes: python scripts/kubesentinel.py setup
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$PassthruArgs
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir

& python "$RepoRoot\scripts\kubesentinel.py" setup @PassthruArgs
exit $LASTEXITCODE

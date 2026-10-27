[CmdletBinding()]
param([string]$AuthorityPython = $env:CONNECT_NA_PYTHON)

$ErrorActionPreference = 'Stop'
$connectRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($AuthorityPython)) {
    $AuthorityPython = Join-Path (Split-Path -Parent $connectRoot) 'genesismesh\.venv\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $AuthorityPython -PathType Leaf)) {
    throw 'Provide -AuthorityPython pointing to the Python environment with Genesis Mesh installed. Live authority tests are required for this gate.'
}
$AuthorityPython = (Resolve-Path -LiteralPath $AuthorityPython).Path
$reportDirectory = Join-Path $connectRoot 'temp\verification'
$null = New-Item -ItemType Directory -Path $reportDirectory -Force
$reportPath = Join-Path $reportDirectory 'latest.json'
$verification = [ordered]@{
    started_at = [DateTimeOffset]::Now.ToString('o')
    scope = 'Windows implementation; Mac archive/signing and physical-device validation remain separate'
    status = 'running'
    steps = @()
}
function Save-Report {
    $verification | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPath -Encoding utf8
}
function Invoke-VerificationStep {
    param([string]$Name, [string]$Executable, [string[]]$Arguments, [string]$Directory = $connectRoot)
    $started = [DateTimeOffset]::Now
    Write-Host "Checking $Name"
    $step = [ordered]@{ name = $Name; command = $Executable; arguments = $Arguments; status = 'running' }
    $verification.steps += $step
    Save-Report
    Push-Location -LiteralPath $Directory
    try {
        & $Executable @Arguments
        if ($LASTEXITCODE -ne 0) { throw "$Name failed with exit code $LASTEXITCODE" }
        $step.status = 'passed'
    } catch {
        $step.status = 'failed'
        throw
    } finally {
        Pop-Location
        $step.elapsed_seconds = [Math]::Round(([DateTimeOffset]::Now - $started).TotalSeconds, 2)
        Save-Report
    }
}
$previousPython = $env:CONNECT_NA_PYTHON
try {
    $env:CONNECT_NA_PYTHON = $AuthorityPython
    Invoke-VerificationStep 'frontend onboarding, browsing and references' 'npm.cmd' @('test') (Join-Path $connectRoot 'apps\connect')
    Invoke-VerificationStep 'owner adapter with real core' $AuthorityPython @('-m', 'unittest', '-v', 'test_owner') (Join-Path $connectRoot 'apps\connect\authority')
    Invoke-VerificationStep 'formatting' 'cargo' @('fmt', '--all', '--', '--check')
    Invoke-VerificationStep 'standalone core library' 'cargo' @('check', '-p', 'connect-core', '--lib', '--locked')
    Invoke-VerificationStep 'iOS DNS parser' 'cargo' @('test', '--manifest-path', 'vendor/n0-dns-resolver/Cargo.toml', '--lib', 'system_config::ios::tests', '--no-default-features', '--locked')
    Invoke-VerificationStep 'Clippy' 'cargo' @('clippy', '--workspace', '--all-targets', '--locked', '--', '-D', 'warnings')
    Invoke-VerificationStep 'workspace tests' 'cargo' @('test', '--workspace', '--all-targets', '--locked')
    Invoke-VerificationStep 'real authority tests' 'cargo' @('test', '--workspace', '--test', 'live_authority', '--locked', '--', '--ignored', '--nocapture')
    Invoke-VerificationStep 'desktop and frontend build' 'npm.cmd' @('run', 'tauri', 'build', '--', '--debug', '--no-bundle', '--ci') (Join-Path $connectRoot 'apps\connect')
    $verification.status = 'passed'
} catch {
    $verification.status = 'failed'
    throw
} finally {
    $env:CONNECT_NA_PYTHON = $previousPython
    $verification.finished_at = [DateTimeOffset]::Now.ToString('o')
    Save-Report
    Write-Host "Verification report: $reportPath"
}

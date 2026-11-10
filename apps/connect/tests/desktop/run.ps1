# Run the desktop journey against the real Windows app, driven by tauri-driver
# with Microsoft Edge WebDriver matching the installed WebView2.
#
# Windows gives the app its data folder and credential store from the signed-in
# account, not from environment variables, so this cannot make a disposable
# world the way run.sh does. It runs only on a throwaway CI runner unless
# -OnThisAccount is given; the journey would create a network in this account's
# Connect data and keys in its Credential Manager.
# Usage: run.ps1 <app.exe> <second_device.exe> [msedgedriver.exe] [-OnThisAccount]
param(
  [Parameter(Mandatory)] [string] $App,
  [Parameter(Mandatory)] [string] $Device,
  [string] $NativeDriver,
  [switch] $OnThisAccount
)
$ErrorActionPreference = 'Stop'
if ($env:CI -ne 'true' -and -not $OnThisAccount) {
  throw 'This journey uses the account''s own Connect data and Credential Manager. Run it on a CI runner, or pass -OnThisAccount.'
}
$here = $PSScriptRoot
$App = (Resolve-Path $App).Path
$Device = (Resolve-Path $Device).Path
$world = Join-Path ([IO.Path]::GetTempPath()) ("connect-journey-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $world | Out-Null

if (-not $NativeDriver) {
  # The driver must match the WebView2 runtime the app runs in.
  $key = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
  $version = (Get-ItemProperty $key).pv
  Write-Host "WebView2 runtime $version"
  $zip = Join-Path $world 'edgedriver.zip'
  Invoke-WebRequest "https://msedgedriver.microsoft.com/$version/edgedriver_win64.zip" -OutFile $zip
  Expand-Archive $zip (Join-Path $world 'edgedriver')
  $NativeDriver = Join-Path $world 'edgedriver\msedgedriver.exe'
}
# The native driver writes a verbose log, kept with the run: a WebView2 that
# never opens its DevTools port is otherwise reported without a cause.
$driverLog = Join-Path $world 'msedgedriver.log'
$wrapper = Join-Path $world 'native-driver.cmd'
"@`"$NativeDriver`" %* --verbose `"--log-path=$driverLog`"" | Set-Content -Encoding ascii $wrapper

# Preflight: the app starts on its own and shows its window. WebDriver reports
# an app that ends at startup only as a missing DevTools port, without the
# app's own output, so say here what it printed.
$log = Join-Path $world 'app'
$first = Start-Process $App -PassThru -RedirectStandardOutput "$log.out" -RedirectStandardError "$log.err"
$shown = $false
foreach ($i in 1..40) {
  Start-Sleep -Milliseconds 500
  $first.Refresh()
  if ($first.HasExited) { break }
  if ($first.MainWindowHandle -ne 0) { $shown = $true; break }
}
$exited = $first.HasExited
if (-not $exited) { $first | Stop-Process -Force; $first.WaitForExit() }
Get-Process | Where-Object { $_.ProcessName -like 'genesismesh-authority*' } | Stop-Process -Force
Get-Process msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (-not $shown) {
  Write-Host "The app did not show its window (exited: $exited, code: $(if ($exited) { $first.ExitCode }))."
  Get-Content "$log.out", "$log.err" -ErrorAction SilentlyContinue | Select-Object -Last 60
  throw 'The app did not start'
}
Write-Host 'Preflight: the app starts and shows its window.'

# Probe: does the app's WebView2 take debugging arguments from the environment,
# as Edge WebDriver passes them, and where does it write DevToolsActivePort?
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = '--remote-debugging-port=9222'
$probe = Start-Process $App -PassThru
$answered = $false
foreach ($i in 1..40) {
  Start-Sleep -Milliseconds 500
  try { $v = Invoke-RestMethod http://127.0.0.1:9222/json/version -TimeoutSec 2; $answered = $true; break } catch { }
}
Write-Host "Probe: DevTools on 9222 answered: $answered $(if ($answered) { $v.Browser })"
Get-CimInstance Win32_Process -Filter "Name = 'msedgewebview2.exe'" | Select-Object -First 3 | ForEach-Object {
  $line = $_.CommandLine
  Write-Host ("Probe: webview2 " + ($line.Substring(0, [Math]::Min(600, $line.Length))))
}
Get-ChildItem -Path $env:LOCALAPPDATA, $env:TEMP -Recurse -Filter DevToolsActivePort -ErrorAction SilentlyContinue | Select-Object -First 5 | ForEach-Object { Write-Host "Probe: port file $($_.FullName)" }
$probe | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process msedgewebview2 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item Env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
Start-Sleep -Seconds 2

$driver = Start-Process tauri-driver -ArgumentList '--port', '4444', '--native-driver', $wrapper -PassThru -NoNewWindow
try {
  $ready = $false
  foreach ($i in 1..60) {
    try { Invoke-RestMethod http://127.0.0.1:4444/status | Out-Null; $ready = $true; break } catch { Start-Sleep -Milliseconds 500 }
  }
  if (-not $ready) { throw 'tauri-driver did not start' }
  $env:CONNECT_APP = $App
  $env:CONNECT_DEVICE_SCRIPT = $Device
  $env:CONNECT_WORLD = $world
  if (-not $env:CONNECT_OUT) { $env:CONNECT_OUT = Join-Path $world 'out' }
  node (Join-Path $here 'journey.mjs')
  if ($LASTEXITCODE -ne 0) {
    Write-Host '--- Edge WebDriver log (last 120 lines) ---'
    Get-Content $driverLog -ErrorAction SilentlyContinue | Select-Object -Last 120
    throw "The journey failed with exit code $LASTEXITCODE"
  }
} finally {
  if (Test-Path $driverLog) {
    New-Item -ItemType Directory -Force $env:CONNECT_OUT | Out-Null
    Copy-Item $driverLog $env:CONNECT_OUT
  }
  # Stop the driver, the app, the authority it started and the test device.
  $driver | Stop-Process -Force -ErrorAction SilentlyContinue
  Get-Process msedgedriver, genesismesh-connect, second_device -ErrorAction SilentlyContinue | Stop-Process -Force
  Get-Process | Where-Object { $_.ProcessName -like 'genesismesh-authority*' } | Stop-Process -Force
  Remove-Item -Recurse -Force $world -ErrorAction SilentlyContinue
}

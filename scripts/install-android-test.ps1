[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Apk,
    [ValidateSet('Connect', 'EngineCheck', 'RootCheck')][string]$AppKind = 'Connect',
    [string]$DeviceSerial,
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$JavaHome = 'C:\Program Files\Android\Android Studio\jbr',
    [string]$Python = 'python',
    [string]$DebugKeystore = "$env:USERPROFILE\.android\debug.keystore"
)

$ErrorActionPreference = 'Stop'
$connectRoot = Split-Path -Parent $PSScriptRoot
$package = switch ($AppKind) {
    'EngineCheck' { 'org.genesismesh.connect.authoritycheck' }
    'RootCheck' { 'org.genesismesh.connect.authoritycheck.rootcheck' }
    default { 'org.genesismesh.connect.qualification' }
}
$apkPath = (Resolve-Path -LiteralPath $Apk).Path
if (-not (Test-Path -LiteralPath $apkPath -PathType Leaf)) { throw 'Provide an APK file.' }
$adb = Join-Path $SdkRoot 'platform-tools\adb.exe'
$tools = Join-Path $SdkRoot 'build-tools\36.0.0'
$aapt = Join-Path $tools 'aapt.exe'
$signer = Join-Path $tools 'apksigner.bat'
foreach ($tool in @($adb, $aapt, $signer, (Join-Path $JavaHome 'bin\java.exe'), $DebugKeystore)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required Android development file is missing: $tool" }
}

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Android qualification command failed: $Program (exit $LASTEXITCODE)" }
}

# Read the manifest rather than trusting a filename or a caller-supplied package.
$badging = Invoke-Checked $aapt @('dump', 'badging', $apkPath)
if (@($badging | Where-Object { $_ -match "^package: name='$([regex]::Escape($package))' " }).Count -ne 1) {
    throw 'Refusing APK: it does not match the selected Genesis Mesh development package.'
}
$devices = Invoke-Checked $adb @('devices')
$ready = @($devices | ForEach-Object { if ($_ -match '^(\S+)\s+device$') { $Matches[1] } })
if ([string]::IsNullOrWhiteSpace($DeviceSerial)) {
    if ($ready.Count -ne 1) { throw 'Connect and authorize one phone, or supply -DeviceSerial.' }
    $DeviceSerial = $ready[0]
}
if ($DeviceSerial -notin $ready) { throw 'The requested Android phone is disconnected or USB debugging is not authorized.' }

$savedJavaHome = $env:JAVA_HOME
try {
    $env:JAVA_HOME = $JavaHome
    Invoke-Checked $Python @((Join-Path $PSScriptRoot 'check-android-apk.py'), $apkPath)
    Invoke-Checked $signer @('verify', '--verbose', $apkPath)
    $directory = Join-Path $connectRoot ("temp\android-install\" + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $directory
    $signed = Join-Path $directory 'Connect-Test.apk'
    # The standard Android development key uses a public, fixed debug password.
    # Never accept a production signing alias or request/export a user password.
    Invoke-Checked $signer @('sign', '--ks', $DebugKeystore, '--ks-key-alias', 'androiddebugkey',
        '--ks-pass', 'pass:android', '--key-pass', 'pass:android', '--out', $signed, $apkPath)
    Invoke-Checked $signer @('verify', '--verbose', '--print-certs', $signed)
    Invoke-Checked $Python @((Join-Path $PSScriptRoot 'check-android-apk.py'), $signed)
    Invoke-Checked $adb @('-s', $DeviceSerial, 'install', '-r', $signed)
    # A signature mismatch stops above. Never uninstall or clear application data.
    $activity = @(Invoke-Checked $adb @('-s', $DeviceSerial, 'shell', 'cmd', 'package', 'resolve-activity', '--brief', $package)) |
        Where-Object { $_ -match "^$([regex]::Escape($package))/[A-Za-z0-9_.]+$" } | Select-Object -Last 1
    if (-not $activity) { throw 'Installed APK has no matching launch activity.' }
    Invoke-Checked $adb @('-s', $DeviceSerial, 'shell', 'am', 'start', '-W', '-n', $activity.Trim())
    [ordered]@{
        source_sha256 = (Get-FileHash -LiteralPath $apkPath -Algorithm SHA256).Hash.ToLowerInvariant()
        installed_sha256 = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLowerInvariant()
        package = $package
        installed = $true
        visual_acceptance = 'not_verified_by_installer'
        authority_hosting_accepted = $false
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $directory 'install.json') -Encoding utf8
    Write-Host "Installed $AppKind in place. Verify the phone UI separately. Record: $directory\install.json"
} finally {
    $env:JAVA_HOME = $savedJavaHome
}

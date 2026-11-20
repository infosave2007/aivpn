param([string]$RoutingDriver, [string]$RoutingAltitude)
$ErrorActionPreference = 'Stop'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$packageDir = Join-Path $repoRoot 'releases\aivpn-windows-gui'
$finalOutputExe = Join-Path $repoRoot 'releases\aivpn-windows-installer.exe'
$nsisScript = Join-Path $PSScriptRoot 'aivpn-installer.nsi'
$iconFile = Join-Path $repoRoot 'assets\brand\win\aivpn.ico'

# Build entirely under an ASCII-only root to avoid Windows toolchain path issues.
$buildRoot = 'C:\AIVPNBUILD-' + [Guid]::NewGuid().ToString('N')
$stageDir = Join-Path $buildRoot 'stage'
$intermediateOutputExe = Join-Path $buildRoot 'aivpn-windows-installer.exe'
$makensis = 'C:\Program Files (x86)\NSIS\makensis.exe'

$cargoToml = Join-Path $repoRoot 'Cargo.toml'
if (-not (Test-Path $cargoToml)) {
    throw 'Missing workspace Cargo.toml.'
}
$match = Select-String -Path $cargoToml -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $match -or $match.Matches.Count -eq 0) {
    throw 'Unable to determine the application version from Cargo.toml.'
}
$appVersion = $match.Matches[0].Groups[1].Value

if (-not (Test-Path (Join-Path $packageDir 'aivpn.exe'))) {
    throw 'Missing releases\\aivpn-windows-package\\aivpn.exe. Build the release package first.'
}

if (-not (Test-Path $nsisScript)) {
    throw 'Missing windows-installer\\aivpn-installer.nsi.'
}

if (-not (Test-Path $iconFile)) {
    throw 'Missing aivpn-windows\\assets\\aivpn.ico.'
}

if (-not (Test-Path $makensis)) {
    throw 'NSIS is not installed at C:\Program Files (x86)\NSIS\makensis.exe.'
}

New-Item -ItemType Directory -Path $buildRoot | Out-Null
try {
    New-Item -ItemType Directory -Path $stageDir | Out-Null
    # Ресурсы DLL/SYS уже включены в EXE во время сборки.
    if ($RoutingDriver -or $RoutingAltitude) {
        throw 'Задайте AIVPN_ROUTING_DRIVER и AIVPN_ROUTING_ALTITUDE перед сборкой EXE, затем подготовьте routing-bootstrap.nsh.'
    }
    Copy-Item (Join-Path $packageDir 'aivpn.exe') $stageDir
    $capabilities = (& (Join-Path $packageDir 'aivpn.exe') --capabilities) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Не удалось проверить ресурсы общего образа.' }
    $routingEnabled = if ($capabilities.app_routing.compiled -and $capabilities.resources.routing_driver) { 1 } else { 0 }
    [IO.File]::WriteAllText((Join-Path $stageDir 'routing-bootstrap.nsh'),("!define ROUTING_ENABLED " + $routingEnabled))
    Copy-Item $iconFile $stageDir

    & $makensis /V2 /DAPP_VERSION=$appVersion /DSTAGE_DIR=$stageDir /DOUTPUT_EXE=$intermediateOutputExe $nsisScript
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $intermediateOutputExe)) {
        throw 'NSIS did not create the installer executable.'
    }

    $publishedOutputExe = $finalOutputExe
    try {
        Copy-Item $intermediateOutputExe $finalOutputExe -Force
    } catch {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $publishedOutputExe = Join-Path $repoRoot ("releases\aivpn-windows-installer-{0}.exe" -f $timestamp)
        Copy-Item $intermediateOutputExe $publishedOutputExe -Force
    }
    Get-Item $publishedOutputExe | Select-Object FullName, Length, LastWriteTime
} finally {
    # Удаляется только созданный этим запуском каталог с непредсказуемым именем.
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}

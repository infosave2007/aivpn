# Базовая установка единого EXE и Wintun из встроенного комплекта.
[CmdletBinding()]
param([ValidateSet('Install','Uninstall','Prepare')][string]$Action,[Parameter(Mandatory=$true)][string]$SourceDirectory,[bool]$RoutingCompiled=$false)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AIVPN'
$metadata=Join-Path $root 'image-installation.json'
$appMetadata=Join-Path (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AIVPNRouting') 'installation.json'
$system='S-1-5-18';$admins='S-1-5-32-544';$names=@('aivpn.exe','wintun.dll')
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Нужен администратор'}
if (-not (Get-Command Check-Protected -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'windows-setup-common.ps1')
}
function Save-ImageReceipt($Value) {
    $temporary=Join-Path $root ('image-metadata-'+[Guid]::NewGuid().ToString('N'))
    $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 6 -Compress))
    $file=New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    [AivpnSetupFile]::Replace($temporary,"$metadata.pending")
}

function Test-LegacyBackup($Receipt) {
    if(-not $Receipt -or $Receipt.PSObject.Properties.Name -notcontains 'legacy'){return}
    $backup=[string]$Receipt.backup
    if([IO.Path]::GetDirectoryName($backup) -ine $root -or [IO.Path]::GetFileName($backup) -notmatch '^legacy-image-[a-f0-9]{32}$'){throw 'Неверный путь прежней копии'}
    Check-Protected $backup
    $allowed=@('aivpn.exe','wintun.dll','aivpn-client.exe','aivpn-routing-service.exe','aivpn-packet-worker.exe','aivpn-app-control.exe')
    foreach($item in Get-ChildItem -LiteralPath $backup -Force){
        if($item.Name -notin $allowed -or $Receipt.legacy.PSObject.Properties.Name -notcontains $item.Name){throw 'Неизвестный файл прежней копии сохранен'}
        Check-Protected $item.FullName
        if((Hash $item.FullName) -ne $Receipt.legacy.($item.Name)){throw 'Измененная прежняя копия сохранена'}
    }
}

New-ProtectedDirectory $root $true
Check-Protected $root
if(Test-Path -LiteralPath $appMetadata){if($Action -eq 'Uninstall' -or -not $RoutingCompiled){throw 'Сначала штатно удалите app-routing'}}
if($Action -eq 'Uninstall' -and ((Get-Service AivpnAppRouting -ErrorAction SilentlyContinue) -or (Get-CimInstance Win32_SystemDriver -Filter "Name='AivpnAppRoutingDriver'"))){throw 'Сначала завершите удаление службы и драйвера app-routing'}

if($Action -eq 'Install' -and (Test-Path -LiteralPath $appMetadata)){
    Check-Protected $appMetadata;$shared=[IO.File]::ReadAllText($appMetadata)|ConvertFrom-Json
    if($shared.version -ne 2 -or (Hash (Join-Path $SourceDirectory 'aivpn.exe')) -ne $shared.files.'aivpn.exe'){throw 'Общий образ обновляется транзакцией службы'}
}

$lockPath=Join-Path $root 'image-installation.lock'
if(Test-Path -LiteralPath $lockPath){Check-Protected $lockPath}
$lock=New-Object IO.FileStream($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
try {
    $previous=$null;$pending=$null
    foreach($path in @($metadata,"$metadata.pending")){
        if(Test-Path -LiteralPath $path){
            Check-Protected $path;$value=[IO.File]::ReadAllText($path)|ConvertFrom-Json
            if($value.version -ne 1 -or (@($value.files.PSObject.Properties.Name|Sort-Object)-join '|') -ne (($names|Sort-Object)-join '|')){throw 'Поврежден receipt образа'}
            foreach($name in $names){if($value.files.$name -notmatch '^[a-f0-9]{64}$'){throw 'Поврежден хеш образа'}}
            if($path -eq $metadata){$previous=$value}else{$pending=$value}
        }
    }
    # У прежнего NSIS нет хешей. Признаем его только по защищенному HKLM receipt
    # и фиксированному каталогу; старые байты сохраняются отдельно до замены.
    if(-not $previous -and -not $pending -and (Test-Path -LiteralPath (Join-Path $root 'aivpn.exe'))){
        $registration=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AIVPN' -ErrorAction SilentlyContinue
        if(-not $registration -or $registration.InstallLocation.TrimEnd('\') -ine $root.TrimEnd('\') -or $registration.DisplayName -ne 'AIVPN' -or $registration.Publisher -ne 'AIVPN'){throw 'Нет подтвержденной прежней установки; файлы сохранены'}
        $backup=Join-Path $root ('legacy-image-'+[Guid]::NewGuid().ToString('N'))
        New-ProtectedDirectory $backup $false
        $legacy=@{}
        foreach($name in @('aivpn.exe','wintun.dll','aivpn-client.exe','aivpn-routing-service.exe','aivpn-packet-worker.exe','aivpn-app-control.exe')){
            $path=Join-Path $root $name
            if(Test-Path -LiteralPath $path){Check-Protected $path;$legacy[$name]=Hash $path;[IO.File]::Copy($path,(Join-Path $backup $name),$false)}
        }
        $files=@{};foreach($name in $names){if(-not $legacy.ContainsKey($name)){throw 'Неполная прежняя установка'};$files[$name]=$legacy[$name]}
        $previous=[pscustomobject]@{version=1;files=$files;legacy=([pscustomobject]$legacy);backup=$backup}
        Save-ImageReceipt $previous;[AivpnSetupFile]::Replace("$metadata.pending",$metadata)
    }
    foreach($name in $names){
        $path=Join-Path $root $name
        if(Test-Path -LiteralPath $path){
            Check-Protected $path;$actual=Hash $path;$allowed=@()
            if($previous){$allowed+=$previous.files.$name};if($pending){$allowed+=$pending.files.$name}
            if($Action -in @('Install','Prepare') -and (Test-Path -LiteralPath $appMetadata)){
                Check-Protected $appMetadata;$shared=[IO.File]::ReadAllText($appMetadata)|ConvertFrom-Json
                if($shared.version -eq 2){$allowed+=$shared.files.$name}
            }
            if($actual -notin $allowed){throw "Незарегистрированный или измененный файл сохранен: $name"}
        }
    }
    if($Action -eq 'Prepare'){return}
    if($Action -eq 'Uninstall'){
        Test-LegacyBackup $previous
        foreach($name in $names){$path=Join-Path $root $name;if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path}}
        if($previous -and $previous.PSObject.Properties.Name -contains 'legacy'){
            foreach($item in Get-ChildItem -LiteralPath $previous.backup -Force){Remove-Item -LiteralPath $item.FullName}
            Remove-Item -LiteralPath $previous.backup
        }
        Remove-Item -LiteralPath $metadata,"$metadata.pending" -ErrorAction SilentlyContinue
        return
    }
    $files=@{}
    foreach($name in $names){$path=Join-Path $SourceDirectory $name;if(-not(Test-Path -LiteralPath $path)){throw 'Нет встроенного файла образа'};$files[$name]=Hash $path}
    if($pending){foreach($name in $names){if($pending.files.$name -ne $files[$name]){throw 'Продолжите тем же комплектом'}}}
    $next=[pscustomobject]@{version=1;files=$files}
    if($previous -and $previous.PSObject.Properties.Name -contains 'legacy'){
        $next|Add-Member -NotePropertyName legacy -NotePropertyValue $previous.legacy
        $next|Add-Member -NotePropertyName backup -NotePropertyValue $previous.backup
    }
    Save-ImageReceipt $next
    foreach($name in $names){
        $destination=Join-Path $root $name
        if((Test-Path -LiteralPath $destination) -and (Hash $destination) -eq $files[$name]){Set-ReadableImage $destination;continue}
        $temporary=Join-Path $root ('image-'+[Guid]::NewGuid().ToString('N'))
        [IO.File]::Copy((Join-Path $SourceDirectory $name),$temporary,$false)
        try { [AivpnSetupFile]::Replace($temporary,$destination) } finally { Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue }
        Set-ReadableImage $destination
    }
    [AivpnSetupFile]::Replace("$metadata.pending",$metadata)
    if($previous -and $previous.PSObject.Properties.Name -contains 'legacy'){
        foreach($name in @('aivpn-client.exe','aivpn-routing-service.exe','aivpn-packet-worker.exe','aivpn-app-control.exe')){
            $path=Join-Path $root $name
            if(Test-Path -LiteralPath $path){
                Check-Protected $path
                if($previous.legacy.PSObject.Properties.Name -notcontains $name -or (Hash $path) -ne $previous.legacy.$name){throw 'Измененный старый файл сохранен'}
                Remove-Item -LiteralPath $path
            }
        }
    }
    Write-Output 'Единый образ и Wintun установлены.'
} finally {$lock.Dispose()}

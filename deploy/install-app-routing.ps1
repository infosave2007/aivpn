# Установка привилегированных компонентов split по приложениям.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Install','Uninstall')][string]$Action,
    [string]$SourceDirectory = $PSScriptRoot,
    [string]$BundleManifest,
    [Guid]$InterfaceGuid = [Guid]::Empty,
    [string]$DnsUpstream = '1.1.1.1:53'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'AivpnAppRouting'
$driverName = 'AivpnAppRoutingDriver'
$root = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AIVPNRouting'
$stateParent = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AIVPN'
$stateRoot = Join-Path $stateParent 'AppRouting'
$metadataPath = Join-Path $root 'installation.json'
$systemSid = 'S-1-5-18'
$adminSid = 'S-1-5-32-544'
$imageRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'AIVPN'
$image = Join-Path $imageRoot 'aivpn.exe'
$names = @('aivpn.exe','wintun.dll','aivpn-app-routing.sys')
$legacyNames = @('aivpn-routing-service.exe','aivpn-packet-worker.exe','aivpn-app-control.exe','aivpn-app-routing.sys')
function Installed-Path([string]$Name) {
    if ($Name -in @('aivpn.exe','wintun.dll')) { return (Join-Path $imageRoot $Name) }
    Join-Path $root $Name
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not [Environment]::Is64BitProcess -or
    -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Нужен 64-разрядный процесс с правами администратора.'
}

if (-not (Get-Command Check-Protected -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'windows-setup-common.ps1')
}

function Invoke-Sc([string[]]$Arguments) {
    Invoke-AivpnSc -Arguments $Arguments
}
function Save-Installation($Value) {
    $temporary = Join-Path $root ('metadata-' + [Guid]::NewGuid().ToString('N'))
    $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 8 -Compress))
    $file = New-Object IO.FileStream($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $file.Write($bytes,0,$bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    [AivpnSetupFile]::Replace($temporary,$metadataPath)
}
function Read-Installation {
    if (-not (Test-Path -LiteralPath $metadataPath)) { return $null }
    Check-Protected $metadataPath
    $value = [IO.File]::ReadAllText($metadataPath) | ConvertFrom-Json
    $expectedNames = if ($value.version -eq 1) { $legacyNames } elseif ($value.version -eq 2) { $names } else { throw 'Неизвестная версия журнала' }
    if ($value.phase -notin @('Installing','Installed','Decommissioned','Purged','Reboot') -or
        (@($value.files.PSObject.Properties.Name | Sort-Object) -join '|') -ne (($expectedNames | Sort-Object) -join '|')) {
        throw 'Поврежден журнал установки.'
    }
    foreach ($name in $expectedNames) {
        if ($value.files.$name -notmatch '^[0-9a-f]{64}$') { throw 'Повреждена контрольная сумма установки.' }
        $path = Installed-Path $name
        if (Test-Path -LiteralPath $path) {
            Check-Protected $path
            $allowed = @($value.files.$name)
            if ($value.phase -eq 'Installing' -and $value.PSObject.Properties.Name -contains 'previousFiles' -and $value.previousFiles) {
                if ($value.previousFiles.PSObject.Properties.Name -contains $name) { $allowed += $value.previousFiles.$name }
            }
            if ((Hash $path) -notin $allowed) { throw "Измененный файл сохранен: $name" }
        } elseif ($value.phase -notin @('Installing','Reboot')) { throw "Пропал файл установки: $name" }
    }
    return $value
}
function Check-Service($Value) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $commands = @($Value.command)
    if ($Value.PSObject.Properties.Name -contains 'previousCommand' -and $Value.previousCommand) { $commands += $Value.previousCommand }
    if ($Value.phase -in @('Decommissioned','Purged','Reboot')) { $commands += Cleanup-Command $Value }
    if ($service -and ($service.StartName -ne 'LocalSystem' -or $service.PathName -notin $commands)) {
        throw 'Регистрация службы не принадлежит этой установке.'
    }
    $driver = Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'"
    if ($driver) {
        $driverPath = $driver.PathName.Trim('"')
        if ($driverPath.StartsWith('\??\')) { $driverPath = $driverPath.Substring(4) }
        if ($driverPath -ne (Join-Path $root 'aivpn-app-routing.sys')) {
            throw 'Регистрация драйвера не принадлежит этой установке.'
        }
    }
}
function Stop-Routing {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') {
        $service.Stop(); $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    }
}
function Cleanup-Command($Value) {
    if ($Value.version -eq 1) { return ('"' + (Join-Path $root 'aivpn-routing-service.exe') + '" --cleanup --purge-state --state-directory "' + $stateRoot + '"') }
    '"' + $image + '" __routing-service --cleanup --purge-state --state-directory "' + $stateRoot + '"'
}
function Run-Cleanup {
    $cleanup = Cleanup-Command $installed
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $changed = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{PathName=$cleanup;StartMode='Manual'}
    if ($changed.ReturnValue -ne 0) { throw 'Не удалось подготовить одноразовую службу очистки.' }
    # Короткая одноразовая служба может завершиться до возврата Start-Service.
    & "$env:SystemRoot\System32\sc.exe" start $serviceName | Out-Null
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $status = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($status.State -eq 'Stopped') { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($status.State -ne 'Stopped' -or $status.ExitCode -ne 0 -or
        (Test-Path -LiteralPath $stateRoot)) { throw 'Очистка не завершена. Файлы сохранены для повторного удаления.' }
}


# Контрольная копия живет отдельно от временного stage и переживает отказ процесса.
function New-UpgradeCheckpoint($Previous) {
    $directory=Join-Path $root ('rollback-'+[Guid]::NewGuid().ToString('N'))
    New-ProtectedDirectory $directory $false
    $hashes=@{};$absent=@()
    foreach($name in @($names+$legacyNames|Select-Object -Unique)){
        $source=Installed-Path $name
        if(Test-Path -LiteralPath $source){
            Check-Protected $source
            [IO.File]::Copy($source,(Join-Path $directory $name),$false)
            $copy=Join-Path $directory $name
            $flush=[IO.File]::Open($copy,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
            try{$flush.Flush($true)}finally{$flush.Dispose()}
            $hashes[$name]=Hash $copy
        }else{$absent+=$name}
    }
    [IO.File]::Copy($metadataPath,(Join-Path $directory 'installation.json'),$false)
    $service=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    $record=[pscustomobject]@{version=1;files=$hashes;absent=$absent;metadata=(Hash $metadataPath);command=$Previous.command;
        running=($service -and $service.State -eq 'Running');startMode=if($service){$service.StartMode}else{'Manual'}}
    $bytes=[Text.Encoding]::UTF8.GetBytes(($record|ConvertTo-Json -Depth 8 -Compress))
    $file=New-Object IO.FileStream((Join-Path $directory 'checkpoint.json'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
    return [IO.Path]::GetFileName($directory)
}
function Restore-Upgrade([string]$Name) {
    if($Name -notmatch '^rollback-[a-f0-9]{32}$'){throw 'Неверный журнал отката'}
    $directory=Join-Path $root $Name
    Check-Protected $directory
    $recordPath=Join-Path $directory 'checkpoint.json';Check-Protected $recordPath
    $record=[IO.File]::ReadAllText($recordPath)|ConvertFrom-Json
    if($record.version -ne 1 -or $record.startMode -notin @('Auto','Manual','Disabled')){throw 'Поврежден журнал отката'}
    $metadata=Join-Path $directory 'installation.json';Check-Protected $metadata
    if((Hash $metadata) -ne $record.metadata){throw 'Изменен прежний receipt'}
    $previous=[IO.File]::ReadAllText($metadata)|ConvertFrom-Json
    if($record.command -cne $previous.command){throw 'Изменена прежняя команда службы'}
    $allowed=@($names+$legacyNames|Select-Object -Unique)
    foreach($entry in $record.files.PSObject.Properties){
        if($entry.Name -notin $allowed -or $entry.Value -notmatch '^[a-f0-9]{64}$'){throw 'Поврежден список отката'}
        $source=Join-Path $directory $entry.Name;Check-Protected $source
        if((Hash $source) -ne $entry.Value){throw 'Изменена контрольная копия'}
    }
    foreach($name in $record.absent){if($name -notin $allowed){throw 'Поврежден список отсутствовавших файлов'}}
    $current=Read-Installation
    Stop-Routing
    foreach($entry in $record.files.PSObject.Properties){
        $destination=Installed-Path $entry.Name
        if((Test-Path -LiteralPath $destination) -and (Hash $destination) -eq $entry.Value){continue}
        $temporary=Join-Path ([IO.Path]::GetDirectoryName($destination)) ('restore-'+[Guid]::NewGuid().ToString('N'))
        [IO.File]::Copy((Join-Path $directory $entry.Name),$temporary,$false)
        try{[AivpnSetupFile]::Replace($temporary,$destination)}finally{Remove-Item -LiteralPath $temporary -ErrorAction SilentlyContinue}
    }
    foreach($name in $record.absent){
        $destination=Installed-Path $name
        if(Test-Path -LiteralPath $destination){
            Check-Protected $destination
            if($current.files.PSObject.Properties.Name -notcontains $name -or (Hash $destination) -ne $current.files.$name){throw 'Незарегистрированный файл сохранен при откате'}
            Remove-Item -LiteralPath $destination
        }
    }
    $startMode=@{Auto='auto';Manual='demand';Disabled='disabled'}[$record.startMode]
    Invoke-Sc -Arguments @('config',$serviceName,'binPath=',$record.command,'start=',$startMode)
    $temporary=Join-Path $root ('metadata-'+[Guid]::NewGuid().ToString('N'))
    [IO.File]::Copy($metadata,$temporary,$false);[AivpnSetupFile]::Replace($temporary,$metadataPath)
    if($record.running){
        Invoke-Sc -Arguments @('start',$serviceName)
        (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    }
    Remove-Item -LiteralPath $directory -Recurse -Force
}
function Check-ClassicClients {
    foreach($process in Get-CimInstance Win32_Process -Filter "Name='aivpn.exe'"){
        if($process.ExecutablePath -ieq $image -and $process.CommandLine -match '\s__classic-client\s'){
            throw 'Сначала отключите обычные VPN-подключения AIVPN; служба и файлы сохранены'
        }
    }
}

if ($Action -eq 'Uninstall' -and -not (Test-Path -LiteralPath $root)) {
    if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -or
        (Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'")) {
        throw 'Незарегистрированная служба или драйвер сохранены.'
    }
    Write-Output 'Компоненты split уже удалены.'
    return
}
New-ProtectedDirectory $root $true
New-ProtectedDirectory $imageRoot $true
$lockPath = Join-Path $root 'installation.lock'
if (Test-Path -LiteralPath $lockPath) { Check-Protected $lockPath }
$lock = New-Object IO.FileStream($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$stage = $null
$newDriver = $false
$checkpoint = $null
try {
    $installed = Read-Installation
    if ($installed -and $installed.phase -eq 'Installing' -and $installed.PSObject.Properties.Name -contains 'rollback' -and $installed.rollback) {
        Restore-Upgrade $installed.rollback
        $installed = Read-Installation
    }
    if ($installed) { Check-Service $installed }
    elseif ((Get-Service $serviceName -ErrorAction SilentlyContinue) -or
            (Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'")) {
        throw 'Незарегистрированная служба или драйвер сохранены.'
    }
    if ($Action -eq 'Install') {
        if ($installed -and $installed.phase -notin @('Installed','Installing')) { throw 'Сначала завершите прерванное удаление.' }
        $bundle = $BundleManifest | ConvertFrom-Json
        if ($bundle.version -ne 1 -or $bundle.altitude -notmatch '^[0-9]{1,6}(\.[0-9]{1,16})?$' -or
            (@($bundle.files.PSObject.Properties.Name | Sort-Object) -join '|') -ne (($names | Sort-Object) -join '|')) {
            throw 'Нужен полный комплект с подписанным драйвером и заданной высотой minifilter.'
        }
        $address = $null
        if ($DnsUpstream -notmatch '^([0-9.]+):([0-9]+)$' -or
            -not [Net.IPAddress]::TryParse($Matches[1],[ref]$address) -or
            [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 65535) { throw 'Некорректный DNS upstream.' }
        $stage = Join-Path $root ('stage-' + [Guid]::NewGuid().ToString('N'))
        New-ProtectedDirectory $stage $false
        foreach ($name in $names) {
            if ($bundle.files.$name -notmatch '^[0-9a-f]{64}$') { throw 'Некорректный комплект.' }
            $destination = Join-Path $stage $name
            [IO.File]::Copy((Join-Path $SourceDirectory $name),$destination,$false)
            Check-Protected $destination
            if ((Hash $destination) -ne $bundle.files.$name) { throw "Поврежден файл комплекта: $name" }
            if (-not $installed -and (Test-Path -LiteralPath (Installed-Path $name))) {
                if ($name -notin @('aivpn.exe','wintun.dll') -or (Hash (Installed-Path $name)) -ne $bundle.files.$name) { throw 'Незарегистрированный файл сохранен.' }
            }
        }
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $stage 'aivpn-app-routing.sys')
        if ($signature.Status -ne 'Valid') { throw 'Драйвер не имеет доверенной подписи. Настройки защиты Windows не меняются.' }
        if ($installed -and $installed.files.'aivpn-app-routing.sys' -ne $bundle.files.'aivpn-app-routing.sys') {
            throw 'Перед заменой версии драйвера завершите штатное удаление с перезагрузкой.'
        }
        if ($installed -and $installed.altitude -cne $bundle.altitude) { throw 'Высота установленного minifilter отличается от комплекта.' }
        if ($installed -and $installed.phase -eq 'Installed') {
            Check-ClassicClients
            $checkpoint=New-UpgradeCheckpoint $installed
        }
        if (-not $installed) {
            if ($InterfaceGuid -eq [Guid]::Empty) {
                $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
                    Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}},InterfaceIndex)
                if ($routes.Count -eq 0) { throw 'Нет сетевого адаптера с маршрутом по умолчанию.' }
                $InterfaceGuid = [Guid](Get-NetAdapter -InterfaceIndex $routes[0].InterfaceIndex).InterfaceGuid
            }
            New-ProtectedDirectory $stateParent $false
            if (Test-Path -LiteralPath $stateRoot) { throw 'Незарегистрированное состояние сохранено.' }
            $command = '"' + $image +
                '" __routing-service --state-directory "' + $stateRoot + '" --interface-guid ' + $InterfaceGuid.ToString('B') +
                ' --dns-upstream ' + $DnsUpstream + ' --provenance-volume ' + $env:SystemDrive + '\'
            $installed = [pscustomobject]@{version=2;phase='Installing';command=$command;previousCommand=$null;
                altitude=$bundle.altitude;files=$bundle.files;previousFiles=$null}
        } else {
            if ($installed.version -eq 1) {
                # Драйвер остается на прежнем защищенном пути, меняется только общий EXE.
                $installed | Add-Member -NotePropertyName previousCommand -NotePropertyValue $installed.command -Force
                $prefix = '"' + (Join-Path $root 'aivpn-routing-service.exe') + '" '
                if (-not $installed.command.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Неоднозначная старая команда службы' }
                $installed.command = '"' + $image + '" __routing-service ' + $installed.command.Substring($prefix.Length)
                $installed | Add-Member -NotePropertyName legacyFiles -NotePropertyValue $installed.files -Force
                $installed.version = 2
            }
        }
        # Журнал предшествует изменениям фиксированных файлов и регистрации SCM.
        if ($installed.phase -eq 'Installing') {
            foreach ($name in $names) {
                if ($installed.files.$name -ne $bundle.files.$name) { throw 'Продолжите установку тем же комплектом.' }
            }
        } else {
            $previous = $installed.files
            if($checkpoint){
                # Старый receipt не содержит общий EXE и DLL, контрольная копия содержит.
                $recordPath=Join-Path (Join-Path $root $checkpoint) 'checkpoint.json'
                Check-Protected $recordPath
                $previous=([IO.File]::ReadAllText($recordPath)|ConvertFrom-Json).files
            }
            $installed | Add-Member -NotePropertyName previousFiles -NotePropertyValue $previous -Force
        }
        $installed.files = $bundle.files
        $installed.phase = 'Installing'
        if($checkpoint){$installed|Add-Member -NotePropertyName rollback -NotePropertyValue $checkpoint -Force}
        Save-Installation $installed
        Stop-Routing
        foreach ($name in $names) {
            $destination = Installed-Path $name
            if ($name -eq 'aivpn-app-routing.sys' -and (Test-Path -LiteralPath $destination)) { continue }
            if ((Test-Path -LiteralPath $destination) -and (Hash $destination) -eq $bundle.files.$name) {
                Set-ReadableImage $destination
                continue
            }
            $source = Join-Path $stage $name
            Set-ReadableImage $source
            [AivpnSetupFile]::Replace($source,$destination)
            Check-Protected $destination
        }
        if (-not (Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'")) {
            $newDriver = $true
            Invoke-Sc -Arguments @('create',$driverName,'type=','filesys','start=','system','error=','normal',
                 'binPath=',('"' + (Join-Path $root 'aivpn-app-routing.sys') + '"'),'depend=','FltMgr','group=','FSFilter Activity Monitor')
        }
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$driverName\Parameters\Instances"
        if (-not (Test-Path -LiteralPath "$key\Aivpn App Routing Instance")) {
            New-Item -Path "$key\Aivpn App Routing Instance" -Force | Out-Null
        }
        foreach ($property in @(
            @{Path=$key;Name='DefaultInstance';Value='Aivpn App Routing Instance';PropertyType='String'},
            @{Path="$key\Aivpn App Routing Instance";Name='Altitude';Value=$installed.altitude;PropertyType='String'},
            @{Path="$key\Aivpn App Routing Instance";Name='Flags';Value=0;PropertyType='DWord'})) {
            $old = (Get-Item -LiteralPath $property.Path).GetValue($property.Name,$null)
            if ($null -ne $old -and $old -cne $property.Value) { throw 'Изменена регистрация экземпляра драйвера.' }
            if ($null -eq $old) { New-ItemProperty @property | Out-Null }
        }
        if (-not (Get-Service $serviceName -ErrorAction SilentlyContinue)) {
            New-Service -Name $serviceName -DisplayName 'AIVPN App Routing' -BinaryPathName $installed.command `
                -StartupType Automatic -DependsOn @($driverName,'BFE','nsi') | Out-Null
        }
        Check-Service $installed
        Invoke-Sc -Arguments @('config',$serviceName,'binPath=',$installed.command)
        Invoke-Sc -Arguments @('start',$serviceName)
        (Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
        if ($installed.PSObject.Properties.Name -contains 'legacyFiles' -and $installed.legacyFiles) {
            foreach ($name in $legacyNames | Where-Object { $_ -ne 'aivpn-app-routing.sys' }) {
                $path = Join-Path $root $name
                if (Test-Path -LiteralPath $path) {
                    Check-Protected $path
                    if ((Hash $path) -ne $installed.legacyFiles.$name) { throw 'Старый файл изменился, он сохранен' }
                    Remove-Item -LiteralPath $path
                }
            }
            $installed.legacyFiles = $null
        }
        $installed.phase = 'Installed'; $installed.previousFiles = $null
        if ($installed.PSObject.Properties.Name -contains 'previousCommand') { $installed.previousCommand = $null }
        if($installed.PSObject.Properties.Name -contains 'rollback'){$installed.PSObject.Properties.Remove('rollback')}
        Save-Installation $installed
        if($checkpoint){Remove-Item -LiteralPath (Join-Path $root $checkpoint) -Recurse -Force;$checkpoint=$null}
        if ($newDriver) {
            Write-Output 'Компоненты split установлены. Перезагрузите Windows для захвата новых сеансов приложений с начала загрузки.'
            exit 3010
        }
        Write-Output 'Компоненты split установлены. Политики и профили сохранены.'
    } else {
        if (-not $installed) { Write-Output 'Компоненты split уже удалены.'; return }
        if ($installed.phase -eq 'Installed') {
            if ($installed.version -eq 1) { & (Join-Path $root 'aivpn-app-control.exe') decommission --all-users | Out-Null }
            else { & $image app-routing decommission --all-users | Out-Null }
            if ($LASTEXITCODE -ne 0) { throw 'Не удалось остановить профили и восстановить DNS. Файлы сохранены.' }
            $installed.phase = 'Decommissioned'; Save-Installation $installed
        }
        if ($installed.phase -eq 'Decommissioned') {
            Stop-Routing
            Run-Cleanup
            $installed.phase = 'Purged'; Save-Installation $installed
        }
        if ($installed.phase -eq 'Purged') {
            if (Get-Service $serviceName -ErrorAction SilentlyContinue) { Invoke-Sc -Arguments @('delete',$serviceName) }
            if (Get-CimInstance Win32_SystemDriver -Filter "Name='$driverName'") {
                Invoke-Sc -Arguments @('config',$driverName,'start=','disabled')
                Invoke-Sc -Arguments @('delete',$driverName)
            }
            $installed.phase = 'Reboot'; Save-Installation $installed
        }
        if ($installed.phase -ne 'Reboot') { throw 'Сначала восстановите незавершенную установку.' }
        # Активированный драйвер намеренно сохраняет защиту до перезагрузки.
        $filters = & "$env:SystemRoot\System32\fltmc.exe" filters 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось проверить загруженные minifilter. Файлы сохранены.' }
        $loaded = @($filters | Where-Object { "$_" -match ('^\s*' + [Regex]::Escape($driverName) + '\s+') }).Count -ne 0
        if ($loaded) { Write-Output 'Удаление завершится после перезагрузки и повторного запуска удаления.'; exit 3010 }
        $removalNames = if ($installed.version -eq 1) { $legacyNames } else { $names }
        foreach ($name in $removalNames) {
            $path = Installed-Path $name
            if (Test-Path -LiteralPath $path) {
                Check-Protected $path
                if ((Hash $path) -ne $installed.files.$name) { throw "Измененный файл сохранен: $name" }
            }
        }
        foreach ($name in $removalNames | Where-Object { $_ -notin @('aivpn.exe','wintun.dll') }) { Remove-Item -LiteralPath (Installed-Path $name) -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $metadataPath
        Write-Output 'Компоненты split удалены. Остальные файлы сохранены.'
    }
} catch {
    $failure=$_
    if($checkpoint){
        try{Restore-Upgrade $checkpoint;$checkpoint=$null}
        catch{throw ('Не завершен откат, контрольная копия сохранена: '+$_.Exception.Message+'; исходная ошибка: '+$failure.Exception.Message)}
    }
    throw $failure
} finally {
    if ($stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    $lock.Dispose()
}

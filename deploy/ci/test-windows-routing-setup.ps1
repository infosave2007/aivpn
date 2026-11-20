# Проверяет сценарий Windows PowerShell 5 без установки службы и драйвера.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$source = Join-Path $PSScriptRoot '..\windows-setup-common.ps1'
$tokens = $null
$errors = $null
$tree = [Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path $source).Path,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
$commands = @($tree.FindAll({
    param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Add-Type'
},$true))
if ($commands.Count -ne 1) { throw 'Не найдена единственная проверка файлов установки.' }

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('aivpn-setup-' + [Guid]::NewGuid().ToString('N'))
$originalDirectory = [Environment]::CurrentDirectory
# Установщик работает в каталоге, куда пишут только SYSTEM и администраторы.
# Временный каталог пользователя наследует права записи самого пользователя.
$protected = New-Object Security.AccessControl.DirectorySecurity
$protected.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
$protected.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $protected.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl',
        [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
[IO.Directory]::CreateDirectory($scratch,$protected) | Out-Null
Push-Location -LiteralPath $scratch
try {
    # NSIS кладет свой 32-разрядный System.dll в рабочий каталог. Такая DLL
    # не должна подменять ссылку компилятора на системную .NET-сборку.
    $shadow = Join-Path $scratch 'System.dll'
    Copy-Item "$env:SystemRoot\SysWOW64\kernel32.dll" $shadow
    [Environment]::CurrentDirectory = $scratch
    & ([ScriptBlock]::Create($commands[0].Extent.Text))
    Add-Type -ReferencedAssemblies ([ComponentModel.Win32Exception].Assembly.Location) -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AivpnArgumentProbe {
    [DllImport("shell32.dll", CharSet=CharSet.Unicode)] static extern IntPtr CommandLineToArgvW(string command,out int count);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
    public static string RoundTrip(string argument) {
        int count; var pointer=CommandLineToArgvW("probe.exe "+argument,out count);
        try { if(count!=2) throw new InvalidOperationException("Argument count"); return Marshal.PtrToStringUni(Marshal.ReadIntPtr(pointer,IntPtr.Size)); }
        finally { LocalFree(pointer); }
    }
}
'@
    foreach($argument in @('', 'plain', 'C:\Program Files\AIVPN\aivpn.exe', '"C:\Program Files\AIVPN\aivpn.exe" __routing-service --provenance-volume C:\', 'путь с "кавычками"\')) {
        if([AivpnArgumentProbe]::RoundTrip([AivpnSetupFile]::Quote($argument)) -cne $argument){throw 'Аргумент Windows изменился после кавычек'}
    }
    [AivpnSetupFile]::Check($shadow)
    $systemSid='S-1-5-18';$adminSid='S-1-5-32-544'
    foreach($name in @('Check-Protected','Set-ReadableImage','Hash')) {
        $definition=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
        if($definition.Count -ne 1){throw 'Не найдена проверка ACL'}
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
    }
    Set-ReadableImage $shadow
    $readers=@((Get-Acl $shadow).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IdentityReference.Value -eq 'S-1-5-11' -and $_.AccessControlType -eq 'Allow'})
    if($readers.Count -ne 1 -or ([uint32]$readers[0].FileSystemRights -band 0x500D0156) -ne 0 -or ($readers[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne [Security.AccessControl.FileSystemRights]::ReadAndExecute){throw 'Неверные права запуска образа'}
    $alias = Join-Path $scratch 'second.dll'
    New-Item -ItemType HardLink -Path $alias -Target $shadow | Out-Null
    $refused = $false
    try { [AivpnSetupFile]::Check($shadow) }
    catch {
        if ($_.Exception.GetBaseException() -isnot [InvalidOperationException]) { throw }
        $refused = $true
    }
    if (-not $refused) { throw 'Файл с несколькими жесткими ссылками принят установщиком.' }
    # Проверяем промежуточный receipt миграции старого комплекта до замены EXE.
    $installer=Join-Path $PSScriptRoot '..\install-app-routing.ps1'
    $installTree=[Management.Automation.Language.Parser]::ParseFile((Resolve-Path $installer).Path,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){throw ($errors|Out-String)}
    foreach($name in @('Installed-Path','Save-Installation','Read-Installation')) {
        $definition=@($installTree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
        if($definition.Count -ne 1){throw 'Не найдена функция миграции'}
        . ([ScriptBlock]::Create($definition[0].Extent.Text))
    }
    $phase=@($installTree.FindAll({param($node) $node -is [Management.Automation.Language.IfStatementAst] -and $node.Extent.Text.StartsWith("if (`$installed.phase -eq 'Installing')")},$true))
    if($phase.Count -ne 1){throw 'Не найден переход журнала установки'}
    $root=Join-Path $scratch 'routing';$imageRoot=Join-Path $scratch 'image'
    New-Item -ItemType Directory $root,$imageRoot|Out-Null
    $metadataPath=Join-Path $root 'installation.json'
    $names=@('aivpn.exe','wintun.dll','aivpn-app-routing.sys')
    $legacyNames=@('aivpn-routing-service.exe','aivpn-packet-worker.exe','aivpn-app-control.exe','aivpn-app-routing.sys')
    $oldFiles=@{};$newFiles=@{};$legacyFiles=@{}
    foreach($name in $names){
        $path=Installed-Path $name;[IO.File]::WriteAllText($path,'previous '+$name)
        $oldFiles[$name]=(Get-FileHash $path).Hash.ToLowerInvariant()
        $newFiles[$name]=('a'*64)
    }
    foreach($name in $legacyNames){$legacyFiles[$name]=('b'*64)}
    $checkpoint='rollback-'+[Guid]::NewGuid().ToString('N')
    New-Item -ItemType Directory (Join-Path $root $checkpoint)|Out-Null
    @{files=$oldFiles}|ConvertTo-Json -Depth 8|Set-Content (Join-Path $root ($checkpoint+'\checkpoint.json')) -Encoding UTF8
    $installed=[pscustomobject]@{version=2;phase='Installed';files=[pscustomobject]$legacyFiles}
    . ([ScriptBlock]::Create($phase[0].Extent.Text))
    $installed.files=[pscustomobject]$newFiles;$installed.phase='Installing'
    Save-Installation $installed
    $null=Read-Installation
    [IO.File]::AppendAllText((Installed-Path 'aivpn.exe'),'unregistered')
    $refused=$false
    try{$null=Read-Installation}catch{$refused=$true}
    if(-not $refused){throw 'Миграция приняла неизвестный образ'}
    @{legacy_rollback_receipt=$true;parser_errors=0;native_argument_roundtrip=$true;normal_user_read_only=$true;shadow_reference_ignored=$true;ordinary_file_accepted=$true;
      hard_link_refused=$true} | ConvertTo-Json -Compress
} finally {
    Pop-Location
    [Environment]::CurrentDirectory = $originalDirectory
    Remove-Item -LiteralPath $scratch -Recurse -Force
}

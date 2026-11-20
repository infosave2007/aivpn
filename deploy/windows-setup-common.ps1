$systemSid='S-1-5-18'
$adminSid='S-1-5-32-544'
# Полный путь исключает одноименную DLL из рабочего каталога установщика.
Add-Type -ReferencedAssemblies ([ComponentModel.Win32Exception].Assembly.Location) -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class AivpnSetupFile {
    public static string Quote(string argument) {
        var value = new System.Text.StringBuilder("\"");
        int slashes = 0;
        foreach(char character in argument) {
            if(character == '\\') { slashes++; continue; }
            value.Append('\\', character == '\"' ? slashes * 2 + 1 : slashes);
            value.Append(character); slashes = 0;
        }
        value.Append('\\', slashes * 2); value.Append('\"');
        return value.ToString();
    }
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool MoveFileEx(string source, string destination, uint flags);
    public static void Replace(string source, string destination) {
        if(!MoveFileEx(source,destination,9))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void Check(string name) {
        using(var file=CreateFile(name, 0x80, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero)) {
            Info info;
            if(file.IsInvalid || !GetFileInformationByHandle(file,out info))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            if((info.Attributes & 0x400)!=0 || ((info.Attributes & 0x10)==0 && info.Links!=1))
                throw new InvalidOperationException("Ссылка вместо собственного файла: "+name);
        }
    }
}
'@

function Check-Protected([string]$Path) {
    [AivpnSetupFile]::Check($Path)
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @($systemSid,$adminSid)) { throw "Чужой владелец: $Path" }
    # WRITE_DATA, APPEND_DATA, WRITE_EA, WRITE_ATTRIBUTES, DELETE_CHILD,
    # DELETE, WRITE_DAC, WRITE_OWNER и общие права записи.
    $writeMask = [uint32]0x500D0156
    foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ([uint32]$rule.FileSystemRights -band $writeMask) -ne 0 -and
            $rule.IdentityReference.Value -notin @($systemSid,$adminSid)) {
            throw "Каталог или файл доступен для чужой записи: $Path"
        }
    }
}

function New-ProtectedDirectory([string]$Path,[bool]$Readable) {
    if (Test-Path -LiteralPath $Path) { Check-Protected $Path; return }
    $parent = Split-Path -Parent $Path
    [AivpnSetupFile]::Check($parent)
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier($adminSid)))
    $acl.SetAccessRuleProtection($true,$false)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    foreach ($sid in @($systemSid,$adminSid)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl',
            $inherit, 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    if ($Readable) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')),
            'ReadAndExecute',$inherit,'None','Allow')))
    }
    [IO.Directory]::CreateDirectory($Path,$acl) | Out-Null
    Check-Protected $Path
}

function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }

# PowerShell 5 теряет кавычки при прямом вызове sc.exe с составным binPath.
function Invoke-AivpnSc([string[]]$Arguments) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path $env:SystemRoot 'System32\sc.exe'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.Arguments=(@($Arguments|ForEach-Object{[AivpnSetupFile]::Quote($_)}) -join ' ')
    $process=[Diagnostics.Process]::Start($info)
    try {
        $output=$process.StandardOutput.ReadToEnd();$errorText=$process.StandardError.ReadToEnd();$process.WaitForExit()
        if($process.ExitCode -ne 0){throw "Ошибка SCM ($($process.ExitCode)): $($Arguments[0]); $output $errorText"}
    } finally {$process.Dispose()}
}

# Перенос из закрытого stage сохраняет его ACL. Пользователям нужен только RX.
function Set-ReadableImage([string]$Path) {
    Check-Protected $Path
    $acl=New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'Allow')))
    }
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier('S-1-5-11')), 'ReadAndExecute', 'Allow')))
    [IO.File]::SetAccessControl($Path,$acl)
    Check-Protected $Path
}

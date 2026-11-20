# Снимок выделений драйвера без открытия его управляющего канала.
$ErrorActionPreference = 'Stop'
if ([IntPtr]::Size -ne 8) { throw 'Проверка рассчитана на Windows x64' }
if (-not ('AivpnPoolProbe' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public static class AivpnPoolProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct PoolTag {
        public uint Tag, PagedAllocs, PagedFrees;
        public UIntPtr PagedUsed;
        public uint NonPagedAllocs, NonPagedFrees;
        public UIntPtr NonPagedUsed;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PoolInfo { public uint Count; public PoolTag First; }
    public sealed class Row {
        public string tag;
        public uint paged_allocations, paged_frees, nonpaged_allocations, nonpaged_frees;
        public ulong paged_bytes, nonpaged_bytes;
    }
    [DllImport("ntdll.dll", ExactSpelling = true)]
    static extern int NtQuerySystemInformation(int informationClass, IntPtr buffer,
                                               int length, out int required);
    public static Row[] Read() {
        int length = 1024 * 1024;
        while (length <= 16 * 1024 * 1024) {
            IntPtr buffer = Marshal.AllocHGlobal(length);
            try {
                int required;
                int status = NtQuerySystemInformation(22, buffer, length, out required);
                if (status == unchecked((int)0xc0000004) || status == unchecked((int)0xc0000023)) {
                    length = Math.Max(length * 2, required);
                    continue;
                }
                if (status < 0) throw new InvalidOperationException("Pool query NTSTATUS=" + status.ToString("X8"));
                uint count = unchecked((uint)Marshal.ReadInt32(buffer));
                int first = Marshal.OffsetOf(typeof(PoolInfo), "First").ToInt32();
                int stride = Marshal.SizeOf(typeof(PoolTag));
                if (required < first || required > length || count > (required - first) / stride)
                    throw new InvalidOperationException("Invalid pool query length");
                var rows = new List<Row>();
                for (int i = 0; i < count; i++) {
                    var value = (PoolTag)Marshal.PtrToStructure(IntPtr.Add(buffer, first + i * stride), typeof(PoolTag));
                    string tag = Encoding.ASCII.GetString(BitConverter.GetBytes(value.Tag));
                    if (tag != "AvRi" && tag != "AvRp" && tag != "AVpr") continue;
                    rows.Add(new Row { tag = tag, paged_allocations = value.PagedAllocs,
                        paged_frees = value.PagedFrees, nonpaged_allocations = value.NonPagedAllocs,
                        nonpaged_frees = value.NonPagedFrees, paged_bytes = value.PagedUsed.ToUInt64(),
                        nonpaged_bytes = value.NonPagedUsed.ToUInt64() });
                }
                if (rows.Count != 3) throw new InvalidOperationException("Driver pool tags not found");
                return rows.ToArray();
            } finally { Marshal.FreeHGlobal(buffer); }
        }
        throw new InvalidOperationException("Pool query exceeded its memory bound");
    }
}
'@
}
[AivpnPoolProbe]::Read()

# ScanHub — полная очистка оперативной памяти (как Mem Reduct).
# Запускается задачей планировщика «ScanHub\MemClean» с правами администратора, делает одну очистку и выходит.
# Результат пишет в %ProgramData%\ScanHub\memclean.json.
param([switch]$Standby)            # -Standby: дополнительно очистить весь кэш standby (агрессивнее)
$ErrorActionPreference = 'SilentlyContinue'
$dir = Join-Path $env:ProgramData 'ScanHub'
$out = Join-Path $dir 'memclean.json'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class ScanHubMem {
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    struct TokenPriv { public int Count; public long Luid; public int Attr; }
    [StructLayout(LayoutKind.Sequential)]
    struct FileCacheInfo {
        public UIntPtr CurrentSize, PeakSize; public uint PageFaultCount;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet, CurrentSizeIncludingTransitionInPages, PeakSizeIncludingTransitionInPages;
        public uint TransitionRePurposeCount, Flags;
    }
    [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref int info, int len);
    [DllImport("ntdll.dll")] static extern int NtSetSystemInformation(int cls, ref FileCacheInfo info, int len);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPriv state, int len, IntPtr prev, IntPtr ret);

    public static bool Privilege(string name) {
        IntPtr token;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x28, out token)) return false;   // ADJUST_PRIVILEGES | QUERY
        TokenPriv tp = new TokenPriv(); tp.Count = 1; tp.Attr = 2;                                       // SE_PRIVILEGE_ENABLED
        if (!LookupPrivilegeValue(null, name, out tp.Luid)) return false;
        return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
    }
    // SystemMemoryListInformation (80): 2 — рабочие наборы, 3 — изменённые страницы, 4 — весь standby, 5 — standby с низким приоритетом
    public static int MemoryList(int command) { return NtSetSystemInformation(80, ref command, 4); }
    // SystemFileCacheInformationEx (81): сбросить системный файловый кэш
    public static int FileCache() {
        FileCacheInfo info = new FileCacheInfo();
        info.MinimumWorkingSet = new UIntPtr(ulong.MaxValue);
        info.MaximumWorkingSet = new UIntPtr(ulong.MaxValue);
        return NtSetSystemInformation(81, ref info, Marshal.SizeOf(typeof(FileCacheInfo)));
    }
}
"@

function Avail { [long](Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory * 1KB }
$before = Avail
$r = [ordered]@{ t = [DateTimeOffset]::Now.ToUnixTimeSeconds(); started = [DateTimeOffset]::Now.ToUnixTimeMilliseconds() }
$r.priv_profile = [ScanHubMem]::Privilege('SeProfileSingleProcessPrivilege')
$r.priv_quota   = [ScanHubMem]::Privilege('SeIncreaseQuotaPrivilege')
$r.working_sets = [ScanHubMem]::MemoryList(2)
$r.file_cache   = [ScanHubMem]::FileCache()
$r.modified     = [ScanHubMem]::MemoryList(3)
$r.standby      = if ($Standby) { [ScanHubMem]::MemoryList(4) } else { [ScanHubMem]::MemoryList(5) }
$r.standby_full = [bool]$Standby
$r.free_before = $before
$r.free_after  = Avail
$r.t = [DateTimeOffset]::Now.ToUnixTimeSeconds()
$tmp = "$out.tmp"
($r | ConvertTo-Json -Compress) | Set-Content -Encoding UTF8 -Path $tmp
Move-Item -Force -Path $tmp -Destination $out

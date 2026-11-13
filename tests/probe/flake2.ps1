# THROWAWAY MEASUREMENT (flake 2): who holds the removal's copy of the binary when `del` fails.
# Started before `uninstall --finish`; signals <Out>\r<Tag>.ready when warm; then waits for .ok (copy deleted: exits) or
# .fail (copy still there after `del`): snapshots the holders at once and again until the copy can be deleted.
param([string]$Copy, [string]$Out, [string]$Tag)
$ErrorActionPreference = 'Continue'
$g = Join-Path $Out "r$Tag"
$log = "$g.log"

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

public static class Probe {
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    [DllImport("ntdll.dll")] static extern int RtlAdjustPrivilege(int priv, bool enable, bool thisThread, out bool old);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint acc, bool inh, uint pid);
    [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint acc, bool inh, uint tid);
    [DllImport("kernel32.dll")] static extern bool DuplicateHandle(IntPtr sp, IntPtr sh, IntPtr tp, out IntPtr th, uint acc, bool inh, uint opt);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder sb, ref int size);
    [DllImport("kernel32.dll")] static extern uint GetProcessId(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint GetProcessIdOfThread(IntPtr h);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] static extern uint GetCurrentThreadId();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public uint dwProcessId; public uint lo; public uint hi;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public uint ApplicationType; public uint AppStatus; public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint h, int flags, StringBuilder key);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nSvc, string[] svc);
    [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[] info, out uint reasons);
    [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);

    public static void Warm() { bool o; RtlAdjustPrivilege(20, true, false, out o); }

    static string ImageOf(IntPtr h) {
        var sb = new StringBuilder(1024); int n = sb.Capacity;
        return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null;
    }

    static string NameOfPid(uint pid, Dictionary<uint, string> cache) {
        string s;
        if (cache.TryGetValue(pid, out s)) return s;
        var h = OpenProcess(0x1000, false, pid);
        s = h == IntPtr.Zero ? "?" : (ImageOf(h) ?? "?");
        if (h != IntPtr.Zero) CloseHandle(h);
        cache[pid] = s; return s;
    }

    // What the Restart Manager says holds `path`.
    public static string RestartManager(string path) {
        uint h; var key = new StringBuilder(33);
        int r = RmStartSession(out h, 0, key);
        if (r != 0) return "RmStartSession=" + r;
        try {
            r = RmRegisterResources(h, 1, new[] { path }, 0, IntPtr.Zero, 0, null);
            if (r != 0) return "RmRegisterResources=" + r;
            uint need = 0, count = 0, reasons;
            r = RmGetList(h, out need, ref count, null, out reasons);
            if (r == 0) return "no holders";
            if (r != 234) return "RmGetList=" + r;
            var info = new RM_PROCESS_INFO[need]; count = need;
            r = RmGetList(h, out need, ref count, info, out reasons);
            if (r != 0) return "RmGetList(2)=" + r;
            var sb = new StringBuilder();
            for (int i = 0; i < count; i++)
                sb.Append("pid " + info[i].dwProcessId + " " + info[i].strAppName + " svc=" + info[i].strServiceShortName + " type=" + info[i].ApplicationType + "; ");
            return sb.ToString();
        } finally { RmEndSession(h); }
    }

    class Target { public uint Pid; public string Image; public bool Alive; public List<string> Holders = new List<string>(); }

    // Every process or thread handle in the system that refers to a process whose image is `copy`, live or exited.
    public static string Handles(string copy) {
        var names = new Dictionary<uint, string>();
        uint me = (uint)Process.GetCurrentProcess().Id;
        IntPtr hp = OpenProcess(0x1000, false, me), ht = OpenThread(0x800, false, GetCurrentThreadId());
        int len = 1 << 22, ret; IntPtr buf = Marshal.AllocHGlobal(len);
        int st;
        while ((st = NtQuerySystemInformation(64, buf, len, out ret)) == unchecked((int)0xC0000004)) {
            Marshal.FreeHGlobal(buf); len = Math.Max(len * 2, ret + (1 << 20)); buf = Marshal.AllocHGlobal(len);
        }
        if (st != 0) { Marshal.FreeHGlobal(buf); return "NtQuerySystemInformation=0x" + st.ToString("x"); }
        long n = Marshal.ReadInt64(buf);
        const int ES = 40;
        int procType = -1, thrType = -1;
        for (long i = 0; i < n; i++) {
            IntPtr e = buf + 16 + (int)(i * ES);
            long pid = Marshal.ReadInt64(e, 8), hv = Marshal.ReadInt64(e, 16);
            int type = (ushort)Marshal.ReadInt16(e, 28);
            if (pid == me && hv == (long)hp) procType = type;
            if (pid == me && hv == (long)ht) thrType = type;
        }
        var targets = new Dictionary<uint, Target>();
        var objToPid = new Dictionary<long, uint>();
        var unq = new List<string[]>();   // holders without query access: object, text
        var owners = new Dictionary<uint, IntPtr>();
        int total = 0, unreachable = 0, procHandles = 0, thrHandles = 0;
        for (long i = 0; i < n; i++) {
            IntPtr e = buf + 16 + (int)(i * ES);
            long obj = Marshal.ReadInt64(e, 0), pid = Marshal.ReadInt64(e, 8), hv = Marshal.ReadInt64(e, 16);
            uint access = (uint)Marshal.ReadInt32(e, 24);
            int type = (ushort)Marshal.ReadInt16(e, 28);
            if (type != procType && type != thrType) continue;
            if (pid == me || pid == 0 || pid == 4) continue;
            bool isProc = type == procType;
            if (isProc) procHandles++; else thrHandles++;
            IntPtr owner;
            if (!owners.TryGetValue((uint)pid, out owner)) { owner = OpenProcess(0x40, false, (uint)pid); owners[(uint)pid] = owner; }
            if (owner == IntPtr.Zero) { unreachable++; continue; }
            IntPtr dup;
            if (!DuplicateHandle(owner, (IntPtr)hv, GetCurrentProcess(), out dup, isProc ? 0x1000u : 0x800u, false, 0)) {
                if (isProc) unq.Add(new[] { obj.ToString(), "pid " + pid + " " + NameOfPid((uint)pid, names) + " PROCESS handle 0x" + hv.ToString("x") + " access 0x" + access.ToString("x") + " (no query access)" });
                continue;
            }
            total++;
            uint tpid = isProc ? GetProcessId(dup) : GetProcessIdOfThread(dup);
            if (tpid != 0) {
                Target t;
                if (!targets.TryGetValue(tpid, out t)) {
                    t = new Target { Pid = tpid };
                    var ph = isProc ? dup : OpenProcess(0x1000, false, tpid);
                    if (ph != IntPtr.Zero) {
                        t.Image = ImageOf(ph);
                        uint code; t.Alive = GetExitCodeProcess(ph, out code) && code == 259;
                        if (!isProc) CloseHandle(ph);
                    }
                    targets[tpid] = t;
                }
                t.Holders.Add("pid " + pid + " " + NameOfPid((uint)pid, names) + (isProc ? " PROCESS" : " THREAD") + " handle 0x" + hv.ToString("x") + " access 0x" + access.ToString("x"));
                if (isProc) objToPid[obj] = tpid;
            }
            CloseHandle(dup);
        }
        foreach (var u in unq) { uint tp; if (objToPid.TryGetValue(long.Parse(u[0]), out tp)) targets[tp].Holders.Add(u[1]); }
        foreach (var o in owners.Values) if (o != IntPtr.Zero) CloseHandle(o);
        CloseHandle(hp); CloseHandle(ht); Marshal.FreeHGlobal(buf);

        var sb = new StringBuilder();
        sb.AppendLine("  table: " + n + " handles; process-type " + procHandles + ", thread-type " + thrHandles + "; owners unopenable " + unreachable);
        int deadOther = 0;
        foreach (var t in targets.Values) {
            bool mine = t.Image != null && string.Equals(t.Image, copy, StringComparison.OrdinalIgnoreCase);
            if (!mine) { if (!t.Alive) deadOther++; continue; }
            sb.AppendLine("  COPY PROCESS pid " + t.Pid + " alive=" + t.Alive + " referenced by:");
            foreach (var h in t.Holders) sb.AppendLine("    " + h);
        }
        sb.AppendLine("  other exited processes still referenced: " + deadOther);
        foreach (var t in targets.Values)
            if (!t.Alive && t.Image == null) sb.AppendLine("  exited process of unknown image pid " + t.Pid + " held by " + string.Join("; ", t.Holders.ToArray()));
        return sb.ToString();
    }

    // Live processes whose image is `copy`.
    public static string Live(string copy) {
        var sb = new StringBuilder();
        foreach (var p in Process.GetProcesses()) {
            var h = OpenProcess(0x1000, false, (uint)p.Id);
            if (h == IntPtr.Zero) continue;
            var img = ImageOf(h); CloseHandle(h);
            if (img != null && string.Equals(img, copy, StringComparison.OrdinalIgnoreCase)) sb.Append("pid " + p.Id + "; ");
        }
        return sb.Length == 0 ? "none" : sb.ToString();
    }
}
'@

function Say([string]$text) {
    $stamp = [DateTime]::UtcNow.ToString('HH:mm:ss.fff')
    Add-Content -LiteralPath $log -Value "$stamp $text"
}

function Snap([string]$label) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $rm = [Probe]::RestartManager($Copy)
    $live = [Probe]::Live($Copy)
    $h = [Probe]::Handles($Copy)
    Say "$label (took $($sw.ElapsedMilliseconds) ms)`n  restart manager: $rm`n  live processes with this image: $live`n$h"
    return "$rm|$live|$($h -replace 'took.*','' -replace 'table:.*','')"
}

[Probe]::Warm()
$null = [Probe]::RestartManager($Copy)
$null = [Probe]::Handles($Copy)
$null = [Probe]::Live($Copy)
Say "warm; copy exists: $(Test-Path -LiteralPath $Copy)"
New-Item -ItemType File -Path "$g.ready" -Force | Out-Null

while ($true) {
    if (Test-Path -LiteralPath "$g.ok") { exit 0 }
    if (Test-Path -LiteralPath "$g.fail") { break }
    Start-Sleep -Milliseconds 5
}

$t0 = (Get-Item -LiteralPath "$g.fail").CreationTimeUtc
$sinceFail = ([DateTime]::UtcNow - $t0).TotalMilliseconds
Say "COPY STILL THERE AFTER del; probe saw the fail flag $([int]$sinceFail) ms after it was written"
Say ("processes: " + ((Get-Process | ForEach-Object { "$($_.Id):$($_.ProcessName)" }) -join ' '))
$last = $null
$i = 0
while ($true) {
    $sig = Snap "snapshot $i, +$([int]([DateTime]::UtcNow - $t0).TotalMilliseconds) ms since the fail flag"
    if ($sig -eq $last) { Say "  (same holders as the previous snapshot)" }
    $last = $sig
    try {
        [IO.File]::Delete($Copy)
        Say "DELETE SUCCEEDED +$([int]([DateTime]::UtcNow - $t0).TotalMilliseconds) ms since the fail flag, after $i failed snapshot(s)"
        break
    } catch {
        Say "  delete failed: $($_.Exception.GetType().Name) HResult=0x$($_.Exception.HResult.ToString('x')) $($_.Exception.Message)"
    }
    $i++
}
$null = Snap "snapshot after the deletion"

try {
    $mp = Get-MpComputerStatus
    Say ("Defender: RealTimeProtectionEnabled=$($mp.RealTimeProtectionEnabled) IoavProtectionEnabled=$($mp.IoavProtectionEnabled) " +
         "BehaviorMonitorEnabled=$($mp.BehaviorMonitorEnabled) OnAccessProtectionEnabled=$($mp.OnAccessProtectionEnabled) " +
         "AMServiceEnabled=$($mp.AMServiceEnabled) AntivirusSignatureVersion=$($mp.AntivirusSignatureVersion)")
} catch { Say "Defender status: $($_.Exception.Message)" }
try {
    $events = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; StartTime = $t0.ToLocalTime().AddMinutes(-3) } -ErrorAction Stop
    Say "Defender operational events in the 3 minutes before: $(@($events).Count)"
    foreach ($e in $events) { Say ("  event $($e.Id) at $($e.TimeCreated.ToUniversalTime().ToString('HH:mm:ss.fff')): " + ($e.Message -replace '\s+', ' ').Substring(0, [Math]::Min(300, $e.Message.Length))) }
} catch { Say "Defender events: $($_.Exception.Message)" }

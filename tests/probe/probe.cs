// THROWAWAY MEASUREMENT (flake 2). Built with csc /platform:x64.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;
using System.IO;

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

    class Target { public uint Pid; public string Image; public bool Alive; public string Times; public List<string> Holders = new List<string>(); }
    [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, int len, out int ret);
    [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h, out long c, out long e, out long k, out long u);
    // The NT path of the image (works for an exited process, where QueryFullProcessImageName does not).
    static string NtImageOf(IntPtr h) {
        IntPtr b = Marshal.AllocHGlobal(2048); int r;
        try {
            if (NtQueryInformationProcess(h, 27, b, 2048, out r) != 0) return null;
            int len = Marshal.ReadInt16(b); IntPtr p = Marshal.ReadIntPtr(b, 8);
            return len == 0 ? null : Marshal.PtrToStringUni(p, len / 2);
        } finally { Marshal.FreeHGlobal(b); }
    }
    static string Times(IntPtr h) {
        long c, e, k, u;
        if (!GetProcessTimes(h, out c, out e, out k, out u)) return "?";
        Func<long, string> f = x => x == 0 ? "-" : DateTime.FromFileTimeUtc(x).ToString("HH:mm:ss.fff");
        return "created " + f(c) + " exited " + f(e);
    }

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
                        t.Image = ImageOf(ph) ?? NtImageOf(ph);
                        t.Times = Times(ph);
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
            bool mine = t.Image != null && (string.Equals(t.Image, copy, StringComparison.OrdinalIgnoreCase) || t.Image.EndsWith(copy.Substring(2), StringComparison.OrdinalIgnoreCase));
            if (!mine) { if (!t.Alive) { deadOther++; sb.AppendLine("  exited process pid " + t.Pid + " " + t.Image + " " + t.Times + " held by " + string.Join("; ", t.Holders.ToArray())); } continue; }
            sb.AppendLine("  COPY PROCESS pid " + t.Pid + " alive=" + t.Alive + " " + t.Times + " referenced by:");
            foreach (var h in t.Holders) sb.AppendLine("    " + h);
        }
        sb.AppendLine("  exited processes referenced, not the copy: " + deadOther);
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
    static string Log;
    static void Say(string s) { File.AppendAllText(Log, DateTime.UtcNow.ToString("HH:mm:ss.fff") + " " + s + "\n"); }
    static string Snap(string copy, out string sig) {
        var sw = Stopwatch.StartNew();
        string rm = RestartManager(copy), live = Live(copy), h = Handles(copy);
        sig = rm + "|" + live + "|" + System.Text.RegularExpressions.Regex.Replace(h, "table:[^\n]*\n", "");
        return "(took " + sw.ElapsedMilliseconds + " ms)\n  restart manager: " + rm + "\n  live processes with this image: " + live + "\n" + h;
    }
    // probe.exe <copy> <out dir> <tag>: run right after `del` failed, in the removal's script.
    public static int Main(string[] a) {
        var t0 = DateTime.UtcNow;
        string copy = a[0]; Log = Path.Combine(a[1], "r" + a[2] + ".log");
        Warm();
        Say("probe started; copy exists: " + File.Exists(copy));
        string last = null; int i = 0;
        while (true) {
            string err = null;
            try { File.Delete(copy); } catch (Exception e) { err = e.GetType().Name + " HResult=0x" + e.HResult.ToString("x") + " " + e.Message; }
            double ms = (DateTime.UtcNow - t0).TotalMilliseconds;
            if (err == null) { Say("DELETE SUCCEEDED +" + (int)ms + " ms after the probe started, after " + i + " failed attempt(s)"); break; }
            string sig, text = Snap(copy, out sig);
            Say("attempt " + i + " failed +" + (int)ms + " ms: " + err);
            if (sig != last) Say("snapshot " + text); else Say("  (same holders as the previous snapshot)");
            last = sig; i++;
        }
        string sig2; Say("snapshot after the deletion " + Snap(copy, out sig2));
        var psi = new ProcessStartInfo("tasklist.exe", "/svc /fo csv") { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true };
        using (var tl = Process.Start(psi)) { string o = tl.StandardOutput.ReadToEnd(); tl.WaitForExit(); Say("tasklist /svc:\n" + o); }
        return 0;
    }
}

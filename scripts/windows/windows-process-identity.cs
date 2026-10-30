using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

// Read-only observation, never process adoption or recovery authority.
// Microsoft API contracts reviewed:
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
// https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystemproduct
// https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem
// Parent IDs are observed parentage, not cryptographically attested lineage.
public static class OwaspAiGoatWindowsProcessIdentity {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct ProcessEntry {
        public uint Size, Usage, Pid;
        public UIntPtr DefaultHeap;
        public uint Module, Threads, ParentPid;
        public int BasePriority;
        public uint Flags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=260)] public string Exe;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
    [DllImport("kernel32.dll", EntryPoint="Process32FirstW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] static extern bool Process32First(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", EntryPoint="Process32NextW", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] static extern bool Process32Next(IntPtr snapshot, ref ProcessEntry entry);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, uint length, out uint returned);
    const uint QueryLimitedAndSynchronize = 0x00001000 | 0x00100000;
    const int MaxAncestors = 32;
    static void Need(bool condition) { if (!condition) throw new InvalidOperationException("WINDOWS_PROCESS_IDENTITY_DENIED"); }
    static void Deadline(Stopwatch clock) { Need(clock.ElapsedMilliseconds < 10000); }
    static bool Pid(uint pid) { return pid > 0 && pid <= Int32.MaxValue; }

    static Dictionary<uint,uint> Parents(Stopwatch clock) {
        Deadline(clock);
        IntPtr snapshot = CreateToolhelp32Snapshot(2, 0); // TH32CS_SNAPPROCESS only.
        Need(snapshot != IntPtr.Zero && snapshot != new IntPtr(-1));
        try {
            ProcessEntry entry = new ProcessEntry();
            entry.Size = (uint)Marshal.SizeOf(typeof(ProcessEntry));
            Need(Process32First(snapshot, ref entry));
            Dictionary<uint,uint> result = new Dictionary<uint,uint>();
            do {
                Deadline(clock);
                Need(result.Count < 65536 && !result.ContainsKey(entry.Pid));
                result.Add(entry.Pid, entry.ParentPid);
            } while (Process32Next(snapshot, ref entry));
            Need(Marshal.GetLastWin32Error() == 18); // ERROR_NO_MORE_FILES only.
            return result;
        } finally { CloseHandle(snapshot); }
    }

    static string TokenSid(IntPtr process) {
        IntPtr token = IntPtr.Zero, buffer = IntPtr.Zero;
        try {
            Need(OpenProcessToken(process, 0x0008, out token)); // TOKEN_QUERY only.
            uint length;
            Need(!GetTokenInformation(token, 1, IntPtr.Zero, 0, out length)
                && Marshal.GetLastWin32Error() == 122 && length >= IntPtr.Size && length <= 8192);
            buffer = Marshal.AllocHGlobal((int)length);
            uint returned;
            int headerLength = IntPtr.Size == 8 ? 16 : 8;
            Need(GetTokenInformation(token, 1, buffer, length, out returned) && returned <= length && returned >= headerLength + 12);
            IntPtr sid = Marshal.ReadIntPtr(buffer); // TOKEN_USER.User.Sid
            // The SID must point within the bounded native TOKEN_USER response.
            long offset = sid.ToInt64() - buffer.ToInt64();
            Need(offset >= headerLength && offset <= returned - 8);
            byte revision = Marshal.ReadByte(sid, 0), count = Marshal.ReadByte(sid, 1);
            Need(revision == 1 && count >= 1 && count <= 15 && offset + 8 + 4 * count <= returned);
            return new SecurityIdentifier(sid).Value;
        } finally {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }

    sealed class Pinned : IDisposable {
        public uint PidValue, ParentPid;
        public ulong Birth;
        public string Sid;
        IntPtr handle;
        public Pinned(uint pid, uint parent) {
            Need(Pid(pid) && (parent == 0 || Pid(parent)));
            PidValue = pid; ParentPid = parent;
            handle = OpenProcess(QueryLimitedAndSynchronize, false, pid);
            try { Need(handle != IntPtr.Zero); Read(out Birth, out Sid); }
            catch { Dispose(); throw; }
        }
        void Read(out ulong birth, out string sid) {
            Need(handle != IntPtr.Zero && WaitForSingleObject(handle, 0) == 258); // WAIT_TIMEOUT = live.
            FileTime creation, exit, kernel, user;
            Need(GetProcessTimes(handle, out creation, out exit, out kernel, out user));
            birth = ((ulong)creation.High << 32) | creation.Low;
            Need(birth > 0 && exit.High == 0 && exit.Low == 0);
            sid = TokenSid(handle);
            Need(WaitForSingleObject(handle, 0) == 258);
        }
        public void Stable(Dictionary<uint,uint> parents) {
            uint parent;
            Need(parents.TryGetValue(PidValue, out parent) && parent == ParentPid);
            ulong birth; string sid;
            Read(out birth, out sid);
            Need(birth == Birth && sid == Sid);
            // Independently reopen the PID. A reused ID must never be accepted
            // merely because the retained original handle is still queryable.
            using (Pinned fresh = new Pinned(PidValue, parent)) {
                Need(fresh.Birth == Birth && fresh.Sid == Sid);
            }
        }
        public Dictionary<string,object> Project() {
            return new Dictionary<string,object> { {"pid", PidValue}, {"ppid", ParentPid},
                {"sid", Sid}, {"creationFileTime", Birth.ToString(CultureInfo.InvariantCulture)} };
        }
        public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
    }

    static string SingletonProperty(string className, string property, Stopwatch clock) {
        Deadline(clock);
        EnumerationOptions options = new EnumerationOptions();
        options.Timeout = TimeSpan.FromSeconds(2); options.ReturnImmediately = true;
        using (ManagementObjectSearcher search = new ManagementObjectSearcher("root\\cimv2", "SELECT " + property + " FROM " + className, options))
        using (ManagementObjectCollection values = search.Get()) {
            string result = null; int count = 0;
            foreach (ManagementObject value in values) using (value) {
                Deadline(clock); Need(++count == 1 && value[property] is string);
                result = (string)value[property];
            }
            Need(count == 1 && result != null); return result;
        }
    }
    static string[] Host(Stopwatch clock) {
        string rawUuid = SingletonProperty("Win32_ComputerSystemProduct", "UUID", clock);
        Guid uuid;
        Need(Regex.IsMatch(rawUuid, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
            && Guid.TryParse(rawUuid, out uuid));
        string canonical = new Guid(rawUuid).ToString("D").ToLowerInvariant();
        Need(canonical != "00000000-0000-0000-0000-000000000000" && canonical != "ffffffff-ffff-ffff-ffff-ffffffffffff");
        string hash;
        using (SHA256 sha = SHA256.Create()) hash = BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(canonical))).Replace("-", "").ToLowerInvariant();
        string boot = SingletonProperty("Win32_OperatingSystem", "LastBootUpTime", clock);
        Need(Regex.IsMatch(boot, "^[0-9]{14}\\.[0-9]{6}[+-][0-9]{3}$"));
        long fileTime = ManagementDateTimeConverter.ToDateTime(boot).ToUniversalTime().ToFileTimeUtc();
        Need(fileTime > 0 && fileTime <= DateTime.UtcNow.ToFileTimeUtc());
        return new string[] { hash, fileTime.ToString(CultureInfo.InvariantCulture) };
    }

    public static Dictionary<string,object> Capture(uint ownerPid) {
        Stopwatch clock = Stopwatch.StartNew();
        List<Pinned> pinned = new List<Pinned>();
        try {
            string currentSid;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) { Need(identity.User != null); currentSid = identity.User.Value; }
            string[] host = Host(clock);
            Dictionary<uint,uint> parents = Parents(clock);
            uint helperPid;
            using (Process self = Process.GetCurrentProcess()) helperPid = (uint)self.Id;
            uint helperParent;
            Need(Pid(ownerPid) && parents.TryGetValue(helperPid, out helperParent) && helperParent == ownerPid);
            // Capture only the caller (helper parent), never arbitrary PID input.
            HashSet<uint> seen = new HashSet<uint>();
            List<object> ancestors = new List<object>();
            Pinned boundary = null; string kind = null; uint pid = ownerPid;
            while (true) {
                Deadline(clock);
                uint parent = 0;
                Need(Pid(pid) && seen.Add(pid) && parents.TryGetValue(pid, out parent));
                Pinned process = new Pinned(pid, parent); pinned.Add(process);
                Need(process.Birth >= UInt64.Parse(host[1], CultureInfo.InvariantCulture));
                if (pinned.Count > 1) Need(process.Birth < pinned[pinned.Count - 2].Birth);
                if (process.Sid != currentSid || process.ParentPid == 0) {
                    Need(ancestors.Count > 0);
                    boundary = process; kind = process.Sid != currentSid ? "foreign-sid" : "root"; break;
                }
                Need(ancestors.Count < MaxAncestors);
                ancestors.Add(process.Project()); pid = process.ParentPid;
            }
            Dictionary<uint,uint> after = Parents(clock);
            foreach (Pinned process in pinned) { Deadline(clock); process.Stable(after); }
            string[] later = Host(clock);
            Need(later[0] == host[0] && later[1] == host[1]);
            // Require one final full parent snapshot and retained live handles
            // after the potentially slower WMI observations too.
            after = Parents(clock);
            Need(after.TryGetValue(helperPid, out helperParent) && helperParent == ownerPid);
            foreach (Pinned process in pinned) { Deadline(clock); process.Stable(after); }
            return new Dictionary<string,object> { {"platform", "win32"}, {"hostSha256", host[0]},
                {"bootFileTime", host[1]}, {"currentSid", currentSid}, {"ancestors", ancestors},
                {"boundary", new Dictionary<string,object> { {"kind", kind}, {"process", boundary.Project()} }},
                {"ancestry", "observed-supported-chain"} };
        } finally { foreach (Pinned process in pinned) process.Dispose(); }
    }

    static void Absent(Dictionary<uint,uint> snapshot, uint[] recordedPids) {
        // Presence always denies, including PID reuse or a foreign token SID.
        // No attempt to adopt/open/terminate a recorded PID. OpenProcess failure
        // is not absence evidence; authority is complete system enumeration.
        foreach (uint pid in recordedPids) Need(!snapshot.ContainsKey(pid));
    }
    public static Dictionary<string,object> ObserveAbsence(uint observerPid, string hostSha256,
            string bootFileTime, string expectedSid, uint[] recordedPids) {
        Stopwatch clock = Stopwatch.StartNew();
        Need(Pid(observerPid) && recordedPids != null && recordedPids.Length >= 1 && recordedPids.Length <= MaxAncestors);
        HashSet<uint> seen = new HashSet<uint>();
        foreach (uint pid in recordedPids) Need(Pid(pid) && seen.Add(pid));
        Need(hostSha256 != null && Regex.IsMatch(hostSha256, "^[a-f0-9]{64}$") && bootFileTime != null
            && Regex.IsMatch(bootFileTime, "^[1-9][0-9]{0,19}$"));
        ulong boot;
        Need(UInt64.TryParse(bootFileTime, NumberStyles.None, CultureInfo.InvariantCulture, out boot) && boot > 0);
        string currentSid;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) { Need(identity.User != null); currentSid = identity.User.Value; }
        Need(expectedSid == currentSid);
        string[] host = Host(clock);
        Need(host[0] == hostSha256 && host[1] == bootFileTime);
        Dictionary<uint,uint> before = Parents(clock);
        uint helperPid;
        using (Process self = Process.GetCurrentProcess()) helperPid = (uint)self.Id;
        uint helperParent = 0, observerParent = 0;
        Need(before.TryGetValue(helperPid, out helperParent) && helperParent == observerPid
            && before.TryGetValue(observerPid, out observerParent));
        Absent(before, recordedPids);
        using (Pinned observer = new Pinned(observerPid, observerParent)) {
            Need(observer.Sid == currentSid && observer.Birth >= boot);
            Dictionary<uint,uint> after = Parents(clock);
            Need(after.TryGetValue(helperPid, out helperParent) && helperParent == observerPid);
            observer.Stable(after); Absent(after, recordedPids);
            string[] later = Host(clock);
            Need(later[0] == host[0] && later[1] == host[1]);
            Dictionary<uint,uint> final = Parents(clock);
            Need(final.TryGetValue(helperPid, out helperParent) && helperParent == observerPid);
            observer.Stable(final); Absent(final, recordedPids); Deadline(clock);
            return new Dictionary<string,object> { {"platform", "win32"}, {"hostSha256", host[0]},
                {"bootFileTime", host[1]}, {"currentSid", currentSid}, {"recordedPids", recordedPids},
                {"observer", observer.Project()}, {"recordedProcessesAbsent", true} };
        }
    }
}

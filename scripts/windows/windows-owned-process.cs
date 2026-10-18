using System;
using System.Globalization;
using System.Runtime.InteropServices;

// One unnamed job and one pinned guardian. No PID-based termination operation.
public sealed class DvaiaOwnedProcessJob : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
        public BasicLimits BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [StructLayout(LayoutKind.Sequential)] struct Accounting {
        public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses;
    }
    [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int kind, ref ExtendedLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int kind, IntPtr data, uint length, out uint returned);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr process, out FileTime creation, out FileTime exit, out FileTime kernel, out FileTime user);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool contained);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
    IntPtr job, guardian;
    uint guardianPid;
    string creation;
    bool assigned;
    static void Need(bool condition) { if (!condition) throw new InvalidOperationException("WINDOWS_OWNED_PROCESS_DENIED"); }
    void Available() { Need(job != IntPtr.Zero); }
    void Live() { Need(guardian != IntPtr.Zero && WaitForSingleObject(guardian, 0) == 258); }
    string Birth() {
        FileTime c,e,k,u;
        Need(GetProcessTimes(guardian,out c,out e,out k,out u));
        return (((ulong)c.High << 32) | c.Low).ToString(CultureInfo.InvariantCulture);
    }
    public DvaiaOwnedProcessJob() {
        job=CreateJobObject(IntPtr.Zero,null); // Default non-inheritable, unnamed.
        try {
            Available();
            ExtendedLimits limits=new ExtendedLimits();
            limits.BasicLimitInformation.LimitFlags=0x00002000; // KILL_ON_JOB_CLOSE only. No breakaway.
            Need(SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimits))));
        } catch { Dispose(); throw; }
    }
    public string Pin(uint pid) {
        Available(); Need(pid > 1 && guardian == IntPtr.Zero && !assigned);
        guardian=OpenProcess(0x00000100 | 0x00000001 | 0x00001000 | 0x00100000,false,pid); // SET_QUOTA, TERMINATE, QUERY_LIMITED, SYNCHRONIZE
        Live();
        bool inJob;
        Need(IsProcessInJob(guardian,IntPtr.Zero,out inJob) && !inJob); // Reject pre-existing/nested-job ambiguity.
        guardianPid=pid; creation=Birth(); Need(creation != "0");
        return creation;
    }
    public void Assign(string expectedCreation) {
        Available(); Live(); Need(!assigned && creation == expectedCreation && Birth() == creation);
        Need(AssignProcessToJobObject(job,guardian));
        assigned=true;
        bool member;
        Need(IsProcessInJob(guardian,job,out member) && member);
        Live(); Need(Birth() == creation);
    }
    public uint[] Members() {
        Available();
        int accountingSize=Marshal.SizeOf(typeof(Accounting));
        IntPtr accounting=Marshal.AllocHGlobal(accountingSize);
        IntPtr ids=IntPtr.Zero;
        try {
            uint returned;
            for (int attempt=0;attempt<8;attempt++) {
            Need(QueryInformationJobObject(job,1,accounting,(uint)accountingSize,out returned));
            Accounting value=(Accounting)Marshal.PtrToStructure(accounting,typeof(Accounting));
            Need(value.ActiveProcesses <= 4096);
            int size=8 + 4096 * IntPtr.Size;
            if(ids==IntPtr.Zero) ids=Marshal.AllocHGlobal(size);
            Need(QueryInformationJobObject(job,3,ids,(uint)size,out returned));
            uint assignedCount=(uint)Marshal.ReadInt32(ids,0), count=(uint)Marshal.ReadInt32(ids,4);
            Need(count <= 4096 && assignedCount <= 4096);
            // Process start/exit can race separate native snapshots. Retry only
            // valid observations; API errors and overflow still fail closed.
            Need(QueryInformationJobObject(job,1,accounting,(uint)accountingSize,out returned));
            Accounting after=(Accounting)Marshal.PtrToStructure(accounting,typeof(Accounting));
            if(count != assignedCount || count != value.ActiveProcesses || count != after.ActiveProcesses
                || value.TotalProcesses != after.TotalProcesses) { System.Threading.Thread.Sleep(1); continue; }
            uint[] result=new uint[count];
            for (int i=0;i<count;i++) {
                ulong raw=IntPtr.Size==8 ? (ulong)Marshal.ReadInt64(ids,8+i*8) : (uint)Marshal.ReadInt32(ids,8+i*4);
                Need(raw > 1 && raw <= UInt32.MaxValue); result[i]=(uint)raw;
            }
            Array.Sort(result);
            for (int i=1;i<result.Length;i++) Need(result[i-1]!=result[i]);
            return result;
            }
            throw new InvalidOperationException("WINDOWS_OWNED_PROCESS_DENIED");
        } finally { if(ids!=IntPtr.Zero)Marshal.FreeHGlobal(ids); Marshal.FreeHGlobal(accounting); }
    }
    public bool GuardianOnly() {
        Need(assigned); Live(); Need(Birth()==creation);
        uint[] ids=Members();
        return ids.Length==1 && ids[0]==guardianPid;
    }
    public void Terminate() { Available(); Need(assigned); Need(TerminateJobObject(job,1)); }
    public void Dispose() {
        // Closing the last job handle kills all members even on helper EOF/failure.
        if(job!=IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; }
        if(guardian!=IntPtr.Zero) { CloseHandle(guardian); guardian=IntPtr.Zero; }
    }
}

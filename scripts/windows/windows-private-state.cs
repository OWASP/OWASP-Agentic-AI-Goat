// This is a fail-closed Win32 foundation, not a live Windows qualification.
// Trust assumption: other processes running as the same Windows SID, SYSTEM,
// local administrators and TrustedInstaller are outside the adversary boundary.
// It offers no replacement, rename, publication or secret rotation operation.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace OwaspAiGoat {
 public static class WindowsPrivateState {
  const int MaxBytes = 1024 * 1024;
  const int MaxDeleteBytes = 4096;
  const uint DeleteAccess = 0x00010000;
  const uint ReadControl = 0x00020000, ReadAttributes = 0x80, ReadData = 1, GenericWrite = 0x40000000;
  const uint ShareRead = 1, OpenExisting = 3, CreateNew = 1;
  const uint OpenReparsePoint = 0x00200000, BackupSemantics = 0x02000000;
  const uint DirectoryAttribute = 0x10, ReparseAttribute = 0x400;
  const uint FileAllAccess = 0x001f01ff, DangerousWrite = 0x000d0150;
  // FILE_ADD_FILE/FILE_ADD_SUBDIRECTORY alone create siblings; they cannot
  // replace pinned components or an atomically created protected leaf. Retain
  // FILE_WRITE_EA/ATTRIBUTES, DELETE_CHILD, DELETE, WRITE_DAC and WRITE_OWNER.
  static uint ExpandedMask(int access) {
   uint mask=unchecked((uint)access);
   if ((mask & 0x10000000)!=0) mask |= FileAllAccess; // GENERIC_ALL
   if ((mask & 0x40000000)!=0) mask |= 0x00120116; // FILE_GENERIC_WRITE
   if ((mask & 0x80000000)!=0) mask |= 0x00120089; // FILE_GENERIC_READ
   if ((mask & 0x20000000)!=0) mask |= 0x001200a0; // FILE_GENERIC_EXECUTE
   return mask & 0x0fffffff;
  }
  // Conservative ACE-order evaluation for each untrusted allow trustee. A
  // preceding deny covers only the exact same SID or Everyone. We do not infer
  // group membership: ambiguous cross-group denies fail closed. A later deny
  // cannot revoke a right already allowed. INHERIT_ONLY is not effective on
  // this directory; inherited effective ACEs are evaluated normally.
  static bool AncestorAclIsSafe(RawSecurityDescriptor security, HashSet<string> trusted) {
   if (security.Owner==null || !trusted.Contains(security.Owner.Value) || (security.ControlFlags & ControlFlags.DiscretionaryAclPresent)==0 || security.DiscretionaryAcl==null) return false;
   Dictionary<string,uint> denied=new Dictionary<string,uint>(StringComparer.OrdinalIgnoreCase);
   uint everyoneDenied=0;
   foreach (GenericAce raw in security.DiscretionaryAcl) {
    CommonAce ace=raw as CommonAce;
    if (ace==null || ace.IsCallback || (ace.AceQualifier!=AceQualifier.AccessAllowed && ace.AceQualifier!=AceQualifier.AccessDenied)) return false;
    if ((ace.AceFlags & AceFlags.InheritOnly)!=0) continue;
    string sid=ace.SecurityIdentifier.Value;
    uint rights=ExpandedMask(ace.AccessMask) & DangerousWrite;
    if (ace.AceQualifier==AceQualifier.AccessDenied) {
     uint prior; denied.TryGetValue(sid,out prior); denied[sid]=prior | rights;
     if (sid=="S-1-1-0") everyoneDenied |= rights;
    } else if (!trusted.Contains(sid)) {
     uint prior; denied.TryGetValue(sid,out prior);
     if ((rights & ~(prior | everyoneDenied))!=0) return false;
    }
   }
   return true;
  }
  const uint PersistentAcls = 8;
  const string SystemSid = "S-1-5-18", AdministratorsSid = "S-1-5-32-544";

  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
   public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
  }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low, High; }
  // FILE_DISPOSITION_INFO uses one-byte BOOLEAN, not the four-byte Win32 BOOL.
  [StructLayout(LayoutKind.Sequential)] struct FileDisposition { public byte DeleteFile; }
  [StructLayout(LayoutKind.Sequential)] struct FileInformation {
   public uint Attributes; public FileTime Creation, Access, Write;
   public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
  }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true, EntryPoint="CreateFileW")] static extern SafeFileHandle CreatePrivateFileW(string name, uint access, uint share, ref SecurityAttributes security, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool CreateDirectoryW(string name, ref SecurityAttributes security);
  [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation info);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder name, uint length, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ReadFile(SafeFileHandle handle, byte[] bytes, uint count, out uint read, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool WriteFile(SafeFileHandle handle, byte[] bytes, uint count, out uint written, IntPtr overlapped);
  [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool FlushFileBuffers(SafeFileHandle handle);
  [DllImport("kernel32.dll", SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetFileInformationByHandle(SafeFileHandle handle, int kind, ref FileDisposition info, uint size);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumeInformationW(string root, StringBuilder volumeName, uint volumeSize, out uint serial, out uint componentLength, out uint flags, StringBuilder fsName, uint fsSize);
  [DllImport("advapi32.dll", SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint security, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint length);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr allocation);

  static void Require(bool condition) { if (!condition) throw new InvalidOperationException("Denied"); }
  static string Normalize(string input) {
   Require(input != null && input.Length <= 240 && Regex.IsMatch(input, @"^[a-zA-Z]:\\") && !Regex.IsMatch(input, @"[\x00-\x1f\x7f/]"));
   string[] parts = input.Substring(3).Split('\\');
   foreach (string part in parts) Require(part.Length > 0 && part != "." && part != ".." && !Regex.IsMatch(part, "[<>:\"|?*]") && !Regex.IsMatch(part, "[. ]$") && !Regex.IsMatch(part, @"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", RegexOptions.IgnoreCase));
   return Char.ToUpperInvariant(input[0]) + input.Substring(1);
  }
  static HashSet<string> Trusted(string user) {
   HashSet<string> trusted = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { user, SystemSid, AdministratorsSid };
   try { trusted.Add(((SecurityIdentifier)new NTAccount("NT SERVICE", "TrustedInstaller").Translate(typeof(SecurityIdentifier))).Value); } catch (IdentityNotMappedException) { }
   return trusted;
  }
  static byte[] Security(SafeFileHandle handle, bool isPrivate, bool directory, string user, HashSet<string> trusted) {
   IntPtr owner, group, dacl, sacl, descriptor;
   Require(GetSecurityInfo(handle, 1, 1 | 4, out owner, out group, out dacl, out sacl, out descriptor) == 0);
   try {
    uint length = GetSecurityDescriptorLength(descriptor); Require(length > 0 && length <= 65536);
    byte[] bytes = new byte[(int)length]; Marshal.Copy(descriptor, bytes, 0, bytes.Length);
    RawSecurityDescriptor security = new RawSecurityDescriptor(bytes, 0);
    Require(security.Owner != null && trusted.Contains(security.Owner.Value));
    Require((security.ControlFlags & ControlFlags.DiscretionaryAclPresent) != 0 && security.DiscretionaryAcl != null);
    if (isPrivate) Require(security.Owner.Value == user && (security.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
    if (!isPrivate) { Require(AncestorAclIsSafe(security,trusted)); return bytes; }
    bool userFull = false;
    foreach (GenericAce raw in security.DiscretionaryAcl) {
     CommonAce ace = raw as CommonAce;
     Require(ace != null && !ace.IsCallback && (ace.AceQualifier == AceQualifier.AccessAllowed || ace.AceQualifier == AceQualifier.AccessDenied));
     if (isPrivate) {
      Require((ace.AceFlags & (AceFlags.Inherited | AceFlags.InheritOnly)) == 0);
      Require(directory || (ace.AceFlags & (AceFlags.ContainerInherit | AceFlags.ObjectInherit)) == 0);
      Require(ace.SecurityIdentifier.Value == user || ace.SecurityIdentifier.Value == SystemSid);
      Require(ace.AceQualifier == AceQualifier.AccessAllowed && unchecked((uint)ace.AccessMask) == FileAllAccess);
      if (ace.SecurityIdentifier.Value == user) userFull = true;
     }
    }
    if (isPrivate) Require(userFull);
    return bytes;
   } finally { LocalFree(descriptor); }
  }
  static FileInformation Information(SafeFileHandle handle, string expectedPath, bool directory) {
   FileInformation info; Require(GetFileInformationByHandle(handle, out info));
   Require((info.Attributes & ReparseAttribute) == 0 && ((info.Attributes & DirectoryAttribute) != 0) == directory);
   if (!directory) Require(info.Links == 1 && info.SizeHigh == 0 && info.SizeLow <= MaxBytes);
   StringBuilder finalName = new StringBuilder(512);
   uint length = GetFinalPathNameByHandleW(handle, finalName, (uint)finalName.Capacity, 0);
   Require(length > 0 && length < finalName.Capacity);
   Require(String.Equals(finalName.ToString(), @"\\?\" + expectedPath, StringComparison.OrdinalIgnoreCase));
   return info;
  }
  static bool Equal(byte[] a, byte[] b) {
   if (a.Length != b.Length) return false; for (int i=0; i<a.Length; i++) if (a[i] != b[i]) return false; return true;
  }
  static void Same(FileInformation a, FileInformation b, bool directory) {
   Require(a.VolumeSerial == b.VolumeSerial && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow && a.Attributes == b.Attributes && a.Creation.Low == b.Creation.Low && a.Creation.High == b.Creation.High);
   if (!directory) Require(a.SizeHigh == b.SizeHigh && a.SizeLow == b.SizeLow && a.Links == b.Links && a.Write.Low == b.Write.Low && a.Write.High == b.Write.High);
  }
  sealed class Opened : IDisposable {
   public SafeFileHandle Handle; public string Path; public bool Directory, Private; public FileInformation Before; public byte[] Acl;
   public Opened(SafeFileHandle handle, string path, bool directory, bool isPrivate, string user, HashSet<string> trusted) {
    Handle=handle; Path=path; Directory=directory; Private=isPrivate;
    try { Require(!Handle.IsInvalid); Before=Information(Handle, Path, Directory); Acl=Security(Handle, Private, Directory, user, trusted); } catch { Handle.Dispose(); throw; }
   }
   public void Recheck(string user, HashSet<string> trusted) { Same(Before, Information(Handle, Path, Directory), Directory); Require(Equal(Acl, Security(Handle, Private, Directory, user, trusted))); }
   public void Dispose() { Handle.Dispose(); }
  }
  static Opened Open(string path, bool directory, bool isPrivate, string user, HashSet<string> trusted) {
   // Hold every ancestor until the operation finishes, excluding write/delete
   // sharing. Existing conflicting writers fail admission; reparse traversal is
   // never accepted. ACL/owner checks exclude untrusted namespace mutation.
   SafeFileHandle handle=CreateFileW(path, ReadControl | ReadAttributes | (directory ? 0 : ReadData), ShareRead, IntPtr.Zero, OpenExisting, OpenReparsePoint | BackupSemantics, IntPtr.Zero);
   return new Opened(handle,path,directory,isPrivate,user,trusted);
  }
  static Opened OpenForDeletion(string path,string user,HashSet<string> trusted) {
   // Exclusive leaf admission prevents conflicting read/write/delete handles.
   // DELETE access is held but no disposition is set until identity and bytes
   // plus every private parent/leaf check have passed.
   SafeFileHandle handle=CreateFileW(path,ReadControl|ReadAttributes|ReadData|DeleteAccess,0,IntPtr.Zero,OpenExisting,OpenReparsePoint,IntPtr.Zero);
   return new Opened(handle,path,false,true,user,trusted);
  }
  static Opened OpenForReadAndFlush(string path,string user,HashSet<string> trusted) {
   // FlushFileBuffers requires GENERIC_WRITE. This existing private leaf is
   // never written or created; reject conflicting writers/delete handles and
   // retain the same private ACL, one-link and no-reparse admission as reads.
   // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
   SafeFileHandle handle=CreateFileW(path,ReadControl|ReadAttributes|ReadData|GenericWrite,ShareRead,IntPtr.Zero,OpenExisting,OpenReparsePoint,IntPtr.Zero);
   return new Opened(handle,path,false,true,user,trusted);
  }
  static IntPtr CreationDescriptor(string user, bool directory) {
   string inheritance = directory ? "OICI" : "";
   string sddl = "O:" + user + "D:P(A;" + inheritance + ";FA;;;" + user + ")(A;" + inheritance + ";FA;;;SY)";
   IntPtr descriptor; uint length;
   Require(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out descriptor,out length)); return descriptor;
  }
  static void CreateDirectory(string path,string user) {
   IntPtr descriptor=CreationDescriptor(user,true);
   try { SecurityAttributes attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,InheritHandle=false };
    if (!CreateDirectoryW(path,ref attributes)) Require(Marshal.GetLastWin32Error()==183);
   } finally { LocalFree(descriptor); }
  }
  static Opened CreateFile(string path,byte[] content,string user,HashSet<string> trusted) {
   IntPtr descriptor=CreationDescriptor(user,false); SafeFileHandle handle;
   try { SecurityAttributes attributes=new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,InheritHandle=false };
    // FlushFileBuffers requires GENERIC_WRITE, not merely FILE_WRITE_DATA.
    // Its file mapping also grants append/EA/attribute writes, READ_CONTROL and
    // SYNCHRONIZE; the creation-time protected DACL already grants full access.
    handle=CreatePrivateFileW(path,ReadControl|ReadAttributes|ReadData|GenericWrite,0,ref attributes,CreateNew,OpenReparsePoint,IntPtr.Zero);
   } finally { LocalFree(descriptor); }
   Require(!handle.IsInvalid);
   using (Opened created=new Opened(handle,path,false,true,user,trusted)) {
    uint written; Require(WriteFile(created.Handle,content,(uint)content.Length,out written,IntPtr.Zero) && written==content.Length);
    Require(FlushFileBuffers(created.Handle));
    FileInformation after=Information(created.Handle,path,false);
    Require(after.VolumeSerial==created.Before.VolumeSerial && after.IndexHigh==created.Before.IndexHigh && after.IndexLow==created.Before.IndexLow && after.SizeLow==content.Length);
    Require(Equal(created.Acl,Security(created.Handle,true,false,user,trusted)));
   }
   // Reopen only after releasing the exclusive creation handle. ACLs block
   // other identities in this interval; same-user mutation is excluded.
   Opened reopened=Open(path,false,true,user,trusted);
   try { Require(Equal(content,Read(reopened,user,trusted))); return reopened; } catch { reopened.Dispose(); throw; }
  }
  static byte[] Read(Opened file,string user,HashSet<string> trusted) {
   byte[] bytes=new byte[(int)file.Before.SizeLow];
   uint read; Require(ReadFile(file.Handle,bytes,(uint)bytes.Length,out read,IntPtr.Zero) && read==bytes.Length);
   byte[] sentinel=new byte[1]; Require(ReadFile(file.Handle,sentinel,1,out read,IntPtr.Zero) && read==0);
   file.Recheck(user,trusted); return bytes;
  }
  public static Dictionary<string,object> Invoke(string operation,string inputPath,string bytesBase64) {
   return Invoke(operation,inputPath,bytesBase64,0,null);
  }
  public static Dictionary<string,object> Invoke(string operation,string inputPath,string bytesBase64,uint expectedVolumeSerial,string expectedFileId) {
   Require(operation=="ensurePrivateDirectory" || operation=="inspectPrivateDirectory" || operation=="inspectWorkspaceDirectory" || operation=="readPrivateFile" || operation=="readPrivateWorkspaceFile" || operation=="createPrivateFile" || operation=="deleteMatchingPrivateFile" || operation=="readAndFlushPrivateFile" || operation=="readAndFlushPrivateWorkspaceFile");
   bool deleting=operation=="deleteMatchingPrivateFile";
   bool flushing=operation=="readAndFlushPrivateFile" || operation=="readAndFlushPrivateWorkspaceFile";
   Require(deleting ? expectedFileId!=null && Regex.IsMatch(expectedFileId,"^[a-f0-9]{16}$") : expectedFileId==null && expectedVolumeSerial==0);
   string path=Normalize(inputPath),root=path.Substring(0,3);
   Require(GetDriveTypeW(root)==3); // local fixed drives only, including no UNC
   uint serial,componentLength,flags; StringBuilder filesystem=new StringBuilder(32);
   // BY_HANDLE_FILE_INFORMATION's 64-bit file ID is not guaranteed unique on
   // ReFS. This foundation admits NTFS only; ReFS requires a 128-bit FileIdInfo
   // protocol before its metadata may be admitted by a future integration.
   Require(GetVolumeInformationW(root,null,0,out serial,out componentLength,out flags,filesystem,(uint)filesystem.Capacity) && (flags & PersistentAcls)!=0 && String.Equals(filesystem.ToString(),"NTFS",StringComparison.OrdinalIgnoreCase));
   byte[] content=null;
   if (operation=="createPrivateFile" || deleting) {
    int limit=deleting ? MaxDeleteBytes : MaxBytes;
    Require(bytesBase64!=null && bytesBase64.Length<=((limit+2)/3)*4);
    content=Convert.FromBase64String(bytesBase64); Require(content.Length<=limit && Convert.ToBase64String(content)==bytesBase64);
   } else Require(bytesBase64==null);
   string user=WindowsIdentity.GetCurrent().User.Value; HashSet<string> trusted=Trusted(user);
   bool workspaceDirectory=operation=="inspectWorkspaceDirectory";
   bool directory=operation=="ensurePrivateDirectory" || operation=="inspectPrivateDirectory" || workspaceDirectory;
   bool workspaceFile=operation=="readPrivateWorkspaceFile" || operation=="readAndFlushPrivateWorkspaceFile";
   bool reading=operation=="readPrivateFile" || workspaceFile || flushing;
   List<Opened> chain=new List<Opened>();
   try {
    chain.Add(Open(root,true,false,user,trusted));
    string[] components=path.Substring(3).Split('\\'); string cursor=root;
    int parents=directory ? components.Length : components.Length-1;
    for (int i=0;i<parents;i++) {
     cursor=(cursor.EndsWith("\\",StringComparison.Ordinal) ? cursor : cursor+"\\")+components[i];
     // Ensure creates only the requested leaf. Missing ordinary parents fail
     // admission instead of accidentally constructing a new home hierarchy.
     if (operation=="ensurePrivateDirectory" && i==parents-1) CreateDirectory(cursor,user);
     // Workspace inspection/reads use the publication ancestor policy for all
     // directories. Private operations keep their existing last-parent rule.
     chain.Add(Open(cursor,true,!workspaceFile && !workspaceDirectory && i==parents-1,user,trusted));
    }
    // Files need an admitted parent. The ordinary-reader API preserves private
    // leaf admission below while permitting a trusted workspace parent.
    Require(directory || parents>0);
    Opened leaf;
    if (directory) leaf=chain[chain.Count-1];
    else { leaf=operation=="createPrivateFile" ? CreateFile(path,content,user,trusted) : deleting ? OpenForDeletion(path,user,trusted) : flushing ? OpenForReadAndFlush(path,user,trusted) : Open(path,false,true,user,trusted); chain.Add(leaf); }
    // The snapshot comes from the held target handle's GetSecurityInfo result.
    // Later byte-exact ACL rechecks below also bind this owner until return.
    if(workspaceDirectory)Require(new RawSecurityDescriptor(leaf.Acl,0).Owner.Value==user);
    if (deleting) {
     Require(leaf.Before.VolumeSerial==expectedVolumeSerial && leaf.Before.IndexHigh.ToString("x8")+leaf.Before.IndexLow.ToString("x8")==expectedFileId);
     Require(leaf.Before.SizeLow==content.Length && leaf.Before.SizeLow<=MaxDeleteBytes);
     Require(Equal(content,Read(leaf,user,trusted)));
    }
    byte[] readBytes=reading ? Read(leaf,user,trusted) : null;
    // Read() has admitted the bounded bytes plus EOF on this same handle.
    // A failed flush returns no bytes; every retained handle's identity and
    // ACL is checked again after the flush. This is a file-buffer barrier only,
    // not a directory fsync or a namespace publication operation.
    if (flushing) Require(FlushFileBuffers(leaf.Handle));
    foreach (Opened item in chain) item.Recheck(user,trusted);
    if (deleting) {
     // Documented FileDispositionInfo=4 marks this exact held file for deletion
     // upon close; no DELETE_ON_CLOSE flag, pathname unlink, or retry fallback.
     // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
     // https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info
     FileDisposition disposition=new FileDisposition {DeleteFile=1};
     Require(SetFileInformationByHandle(leaf.Handle,4,ref disposition,(uint)Marshal.SizeOf(typeof(FileDisposition))));
    }
    Dictionary<string,object> result=new Dictionary<string,object> {
     {"version",1},{"ok",true},{"operation",operation},{"path",path},
     {"size",directory ? (object)null : (object)leaf.Before.SizeLow},
     {"identity",new Dictionary<string,object> {{"volumeSerial",leaf.Before.VolumeSerial},{"fileId",leaf.Before.IndexHigh.ToString("x8")+leaf.Before.IndexLow.ToString("x8")}}}
    };
    if (readBytes!=null) result.Add("bytesBase64",Convert.ToBase64String(readBytes));
    if (deleting) result.Add("deleted",true);
    return result;
   } finally { for (int i=chain.Count-1;i>=0;i--) chain[i].Dispose(); }
  }
 }
}

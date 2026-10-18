// Native Windows publication foundation, not live OS qualification. Same-user
// arbitrary mutation, SYSTEM and privileged administrators are trusted. Mutexes
// serialize cooperating invocations; this is not a CAS against malicious code
// already running as the owner. The native mutex and ancestor handles span the entire transaction.
// No POSIX directory-fsync equivalence is asserted. NTFS WRITE_THROUGH and
// FlushFileBuffers are used at their documented bounds; intents remain retained.
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using Microsoft.Win32.SafeHandles;

namespace Dvaia {
 public static class WindowsPrivatePublication {
  const int MaxBytes=1024*1024;
  const uint GenericRead=0x80000000, GenericWrite=0x40000000, ReadControl=0x20000, ReadAttributes=0x80, Delete=0x10000;
  const uint ShareRead=1, ShareDelete=4, CreateNew=1, OpenExisting=3;
  const uint OpenReparsePoint=0x200000, BackupSemantics=0x2000000, WriteThrough=0x80000000;
  const uint DirectoryAttribute=0x10, ReparseAttribute=0x400, FileAllAccess=0x1f01ff, DangerousWrite=0xd0150;
  const uint MoveReplaceExisting=1, MoveWriteThrough=8;
  const string SystemSid="S-1-5-18", AdministratorsSid="S-1-5-32-544";
  static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
  [StructLayout(LayoutKind.Sequential)] struct Attributes { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low,High; }
  [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public FileTime Creation,Access,Write; public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string path,uint access,uint sharing,IntPtr security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true,EntryPoint="CreateFileW")] static extern SafeFileHandle CreatePrivateFileW(string path,uint access,uint sharing,ref Attributes security,uint disposition,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder path,uint capacity,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ReadFile(SafeFileHandle handle,byte[] bytes,uint count,out uint read,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool WriteFile(SafeFileHandle handle,byte[] bytes,uint count,out uint written,IntPtr overlapped);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool SetFilePointerEx(SafeFileHandle handle,long distance,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool FlushFileBuffers(SafeFileHandle handle);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool MoveFileExW(string source,string target,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool GetVolumeInformationW(string root,StringBuilder name,uint nameSize,out uint serial,out uint componentLength,out uint flags,StringBuilder filesystem,uint fsSize);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle handle,uint type,uint flags,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll")] static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text,uint revision,out IntPtr descriptor,out uint length);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr allocation);

  public sealed class Record {
   public int size {get;set;} public string sha256 {get;set;} public uint volumeSerial {get;set;} public string fileId {get;set;} public string creationTime {get;set;}
  }
  public sealed class Intent {
   public int version {get;set;} public string kind {get;set;} public string userSid {get;set;} public string operationId {get;set;}
   public string targetPath {get;set;} public string intentPath {get;set;} public string stagePath {get;set;} public string originalPath {get;set;} public string resultPath {get;set;}
   public Record originalTarget {get;set;} public Record originalBackup {get;set;} public Record result {get;set;} public Record resultBackup {get;set;}
  }
  static void Require(bool value) { if (!value) throw new InvalidOperationException("Denied"); }
  static bool Equal(byte[] a,byte[] b) { if(a.Length!=b.Length)return false; for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false; return true; }
  static string Hash(byte[] bytes) { using(SHA256 algorithm=SHA256.Create())return BitConverter.ToString(algorithm.ComputeHash(bytes)).Replace("-","").ToLowerInvariant(); }
  static string Normalize(string value) {
   Require(value!=null && value.Length<=240 && Regex.IsMatch(value,@"^[a-zA-Z]:\\") && !Regex.IsMatch(value,@"[\x00-\x1f\x7f/]"));
   foreach(string part in value.Substring(3).Split('\\')) Require(part.Length>0 && part!="." && part!=".." && !Regex.IsMatch(part,"[<>:\"|?*]") && !Regex.IsMatch(part,"[. ]$") && !Regex.IsMatch(part,@"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|CLOCK\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)",RegexOptions.IgnoreCase));
   Utf8.GetByteCount(value); // Reject ill-formed UTF-16 before allocating files.
   return Char.ToUpperInvariant(value[0])+value.Substring(1);
  }
  static uint Expand(int input) {
   uint mask=unchecked((uint)input);
   if((mask&0x10000000)!=0)mask|=FileAllAccess;
   if((mask&0x40000000)!=0)mask|=0x120116;
   if((mask&0x80000000)!=0)mask|=0x120089;
   if((mask&0x20000000)!=0)mask|=0x1200a0;
   return mask&0x0fffffff;
  }
  static HashSet<string> Trusted(string user) {
   HashSet<string> trusted=new HashSet<string>(StringComparer.OrdinalIgnoreCase){user,SystemSid,AdministratorsSid};
   try{trusted.Add(((SecurityIdentifier)new NTAccount("NT SERVICE","TrustedInstaller").Translate(typeof(SecurityIdentifier))).Value);}catch(IdentityNotMappedException){}
   return trusted;
  }
  static byte[] Security(SafeFileHandle handle,bool isPrivate,bool directory,string user,HashSet<string> trusted) {
   IntPtr owner,group,dacl,sacl,descriptor;
   Require(GetSecurityInfo(handle,1,1|4,out owner,out group,out dacl,out sacl,out descriptor)==0);
   try {
    uint length=GetSecurityDescriptorLength(descriptor); Require(length>0 && length<=65536);
    byte[] bytes=new byte[(int)length]; Marshal.Copy(descriptor,bytes,0,bytes.Length);
    RawSecurityDescriptor security=new RawSecurityDescriptor(bytes,0);
    Require(security.Owner!=null && trusted.Contains(security.Owner.Value) && (security.ControlFlags&ControlFlags.DiscretionaryAclPresent)!=0 && security.DiscretionaryAcl!=null);
    if(isPrivate)Require(security.Owner.Value==user && (security.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0);
    Dictionary<string,uint> denied=new Dictionary<string,uint>(StringComparer.OrdinalIgnoreCase); uint everyoneDenied=0; bool userFull=false;
    foreach(GenericAce raw in security.DiscretionaryAcl) {
     CommonAce ace=raw as CommonAce;
     Require(ace!=null && !ace.IsCallback && (ace.AceQualifier==AceQualifier.AccessAllowed || ace.AceQualifier==AceQualifier.AccessDenied));
     string sid=ace.SecurityIdentifier.Value;
     if(isPrivate) {
      Require((ace.AceFlags&(AceFlags.Inherited|AceFlags.InheritOnly))==0 && (directory || (ace.AceFlags&(AceFlags.ContainerInherit|AceFlags.ObjectInherit))==0) && (sid==user || sid==SystemSid) && ace.AceQualifier==AceQualifier.AccessAllowed && unchecked((uint)ace.AccessMask)==FileAllAccess);
      if(sid==user)userFull=true;
     } else {
      // Creation of siblings is safe; mutation of pinned entries is not. Deny
      // coverage is conservative: exact SID/Everyone, in actual ACE order.
      if((ace.AceFlags&AceFlags.InheritOnly)!=0)continue;
      uint rights=Expand(ace.AccessMask)&DangerousWrite, prior; denied.TryGetValue(sid,out prior);
      if(ace.AceQualifier==AceQualifier.AccessDenied){denied[sid]=prior|rights;if(sid=="S-1-1-0")everyoneDenied|=rights;}
      else Require(trusted.Contains(sid) || (rights&~(prior|everyoneDenied))==0);
     }
    }
    if(isPrivate)Require(userFull); return bytes;
   } finally { LocalFree(descriptor); }
  }
  static Info Information(SafeFileHandle handle,string path,bool directory) {
   Info info; Require(GetFileInformationByHandle(handle,out info));
   Require((info.Attributes&ReparseAttribute)==0 && ((info.Attributes&DirectoryAttribute)!=0)==directory);
   if(!directory)Require(info.Links==1 && info.SizeHigh==0 && info.SizeLow<=MaxBytes);
   StringBuilder actual=new StringBuilder(512); uint length=GetFinalPathNameByHandleW(handle,actual,(uint)actual.Capacity,0);
   Require(length>0 && length<actual.Capacity && String.Equals(actual.ToString(),@"\\?\"+path,StringComparison.OrdinalIgnoreCase)); return info;
  }
  static void Same(Info a,Info b,bool directory) {
   Require(a.Volume==b.Volume && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow && a.Creation.High==b.Creation.High && a.Creation.Low==b.Creation.Low && a.Attributes==b.Attributes);
   if(!directory)Require(a.SizeHigh==b.SizeHigh && a.SizeLow==b.SizeLow && a.Links==b.Links && a.Write.High==b.Write.High && a.Write.Low==b.Write.Low);
  }
  sealed class Opened:IDisposable {
   public SafeFileHandle Handle; public string Path; public bool Directory,Private; public Info Before; public byte[] Acl;
   public Opened(SafeFileHandle handle,string path,bool directory,bool isPrivate,string user,HashSet<string> trusted) {
    Handle=handle;Path=path;Directory=directory;Private=isPrivate;
    try{Require(!handle.IsInvalid);Before=Information(handle,path,directory);Acl=Security(handle,isPrivate,directory,user,trusted);}catch{handle.Dispose();throw;}
   }
   public void Check(string user,HashSet<string> trusted){Same(Before,Information(Handle,Path,Directory),Directory);Require(Equal(Acl,Security(Handle,Private,Directory,user,trusted)));}
   public void Dispose(){Handle.Dispose();}
  }
  sealed class Scope:IDisposable {
   public string User; public HashSet<string> Trust; public List<Opened> Held=new List<Opened>();
   public Scope(string user){User=user;Trust=Trusted(user);}
   public void Parents(string file,bool privateParent) {
    string root=file.Substring(0,3); Require(GetDriveTypeW(root)==3);
    uint serial,component,flags;StringBuilder filesystem=new StringBuilder(32);
    Require(GetVolumeInformationW(root,null,0,out serial,out component,out flags,filesystem,(uint)filesystem.Capacity) && (flags&8)!=0 && filesystem.ToString()=="NTFS");
    string[] parts=file.Substring(3).Split('\\');Require(parts.Length>1);string cursor=root;
    Held.Add(Open(root,true,false));
    for(int i=0;i<parts.Length-1;i++){cursor=(cursor.EndsWith("\\",StringComparison.Ordinal)?cursor:cursor+"\\")+parts[i];Held.Add(Open(cursor,true,privateParent && i==parts.Length-2));}
   }
   Opened Open(string path,bool directory,bool isPrivate) {
    // Ancestors forbid delete sharing. Private leaves permit the intended
    // rename while refusing data-write sharing; ACLs forbid other identities
    // from using that delete window. Mutex remains held through the operation.
    uint access=directory?ReadControl|ReadAttributes:GenericRead|GenericWrite|Delete;
    uint sharing=directory?ShareRead:ShareRead|ShareDelete;
    SafeFileHandle handle=CreateFileW(path,access,sharing,IntPtr.Zero,OpenExisting,OpenReparsePoint|BackupSemantics|(directory?0:WriteThrough),IntPtr.Zero);
    return new Opened(handle,path,directory,isPrivate,User,Trust);
   }
   public Opened Maybe(string path) {
    SafeFileHandle handle=CreateFileW(path,GenericRead|GenericWrite|Delete,ShareRead|ShareDelete,IntPtr.Zero,OpenExisting,OpenReparsePoint|WriteThrough,IntPtr.Zero);
    if(handle.IsInvalid){int error=Marshal.GetLastWin32Error();handle.Dispose();Require(error==2);return null;}
    Opened opened=new Opened(handle,path,false,true,User,Trust);Held.Add(opened);return opened;
   }
   public Opened Create(string path,byte[] content) {
    Require(content.Length<=MaxBytes);IntPtr descriptor;uint length;
    Require(ConvertStringSecurityDescriptorToSecurityDescriptorW("O:"+User+"D:P(A;;FA;;;"+User+")(A;;FA;;;SY)",1,out descriptor,out length));
    SafeFileHandle handle;
    try{Attributes attributes=new Attributes{Length=Marshal.SizeOf(typeof(Attributes)),Descriptor=descriptor,InheritHandle=false};handle=CreatePrivateFileW(path,GenericRead|GenericWrite|Delete,ShareRead|ShareDelete,ref attributes,CreateNew,OpenReparsePoint|WriteThrough,IntPtr.Zero);}finally{LocalFree(descriptor);}
    using(Opened created=new Opened(handle,path,false,true,User,Trust)){
     int offset=0;
     while(offset<content.Length){int count=Math.Min(65536,content.Length-offset);byte[] chunk=new byte[count];Buffer.BlockCopy(content,offset,chunk,0,count);uint written;Require(WriteFile(handle,chunk,(uint)count,out written,IntPtr.Zero) && written>0 && written<=count);offset+=(int)written;}
     Require(FlushFileBuffers(handle));Info after=Information(handle,path,false);
     Require(after.Volume==created.Before.Volume && after.IndexHigh==created.Before.IndexHigh && after.IndexLow==created.Before.IndexLow && after.SizeLow==content.Length && Equal(created.Acl,Security(handle,true,false,User,Trust)));
    }
    Opened result=Maybe(path);Require(result!=null && Equal(Read(result),content));return result;
   }
   public byte[] Read(Opened opened) {
    opened.Check(User,Trust);long position;Require(SetFilePointerEx(opened.Handle,0,out position,0) && position==0);
    byte[] bytes=new byte[(int)opened.Before.SizeLow];int offset=0;
    while(offset<bytes.Length){int count=Math.Min(65536,bytes.Length-offset);byte[] chunk=new byte[count];uint read;Require(ReadFile(opened.Handle,chunk,(uint)count,out read,IntPtr.Zero) && read>0 && read<=count);Buffer.BlockCopy(chunk,0,bytes,offset,(int)read);offset+=(int)read;}
    byte[] sentinel=new byte[1];uint extra;Require(ReadFile(opened.Handle,sentinel,1,out extra,IntPtr.Zero) && extra==0);opened.Check(User,Trust);return bytes;
   }
   public void Check(){foreach(Opened opened in Held)if(!opened.Handle.IsClosed)opened.Check(User,Trust);}
   public void Dispose(){for(int i=Held.Count-1;i>=0;i--)Held[i].Dispose();}
  }
  static byte[] Decode(string value) {Require(value!=null && value.Length<=((MaxBytes+2)/3)*4);byte[] bytes=Convert.FromBase64String(value);Require(bytes.Length<=MaxBytes && Convert.ToBase64String(bytes)==value);return bytes;}
  static Record Capture(Opened file,byte[] bytes) {return new Record{size=bytes.Length,sha256=Hash(bytes),volumeSerial=file.Before.Volume,fileId=file.Before.IndexHigh.ToString("x8")+file.Before.IndexLow.ToString("x8"),creationTime=file.Before.Creation.High.ToString("x8")+file.Before.Creation.Low.ToString("x8")};}
  static bool Matches(Opened file,Record expected,byte[] bytes) {
   if(file==null || expected==null)return false;Record actual=Capture(file,bytes);
   return actual.size==expected.size && actual.sha256==expected.sha256 && actual.volumeSerial==expected.volumeSerial && actual.fileId==expected.fileId && actual.creationTime==expected.creationTime;
  }
  static string Scalar(object value){return new JavaScriptSerializer().Serialize(value);}
  static string EncodeRecord(Record value) {
   if(value==null)return "null";
   return "{\"size\":"+Scalar(value.size)+",\"sha256\":"+Scalar(value.sha256)+",\"volumeSerial\":"+Scalar(value.volumeSerial)+",\"fileId\":"+Scalar(value.fileId)+",\"creationTime\":"+Scalar(value.creationTime)+"}";
  }
  static byte[] Encode(Intent intent) {
   // Fixed field order avoids relying on reflection/dictionary enumeration
   // order between independent PowerShell compilation processes.
   string json="{\"version\":"+Scalar(intent.version)+",\"kind\":"+Scalar(intent.kind)+",\"userSid\":"+Scalar(intent.userSid)+",\"operationId\":"+Scalar(intent.operationId)
    +",\"targetPath\":"+Scalar(intent.targetPath)+",\"intentPath\":"+Scalar(intent.intentPath)+",\"stagePath\":"+Scalar(intent.stagePath)+",\"originalPath\":"+Scalar(intent.originalPath)+",\"resultPath\":"+Scalar(intent.resultPath)
    +",\"originalTarget\":"+EncodeRecord(intent.originalTarget)+",\"originalBackup\":"+EncodeRecord(intent.originalBackup)+",\"result\":"+EncodeRecord(intent.result)+",\"resultBackup\":"+EncodeRecord(intent.resultBackup)+"}\n";
   return Utf8.GetBytes(json);
  }
  static Intent Parse(byte[] bytes,string target,string intentPath,string id,string user) {
   JavaScriptSerializer serializer=new JavaScriptSerializer();serializer.MaxJsonLength=MaxBytes;serializer.RecursionLimit=8;
   Intent intent=serializer.Deserialize<Intent>(Utf8.GetString(bytes));Require(intent!=null && Equal(Encode(intent),bytes));
   Require(intent.version==1 && intent.kind=="windows-private-publication" && intent.userSid==user && intent.operationId==id && intent.targetPath==target && intent.intentPath==intentPath && intent.stagePath==Normalize(target+".dvaia-"+id+".stage") && intent.result!=null && intent.resultBackup!=null && intent.resultPath==Normalize(intentPath+".result"));
   Require((intent.originalTarget==null)==(intent.originalBackup==null));
   Require(intent.originalPath==(intent.originalTarget==null?null:Normalize(intentPath+".original")));
   Require(intent.result.size>=0 && intent.result.size<=MaxBytes && intent.result.size==intent.resultBackup.size && intent.result.sha256==intent.resultBackup.sha256);
   if(intent.originalTarget!=null)Require(intent.originalTarget.size==intent.originalBackup.size && intent.originalTarget.sha256==intent.originalBackup.sha256);
   return intent;
  }
  static Mutex Locked(string target,string user) {
   MutexSecurity security=new MutexSecurity();SecurityIdentifier owner=new SecurityIdentifier(user),system=new SecurityIdentifier(SystemSid);
   security.SetOwner(owner);security.SetAccessRuleProtection(true,false);security.AddAccessRule(new MutexAccessRule(owner,MutexRights.FullControl,AccessControlType.Allow));security.AddAccessRule(new MutexAccessRule(system,MutexRights.FullControl,AccessControlType.Allow));
   bool created;Mutex mutex=new Mutex(false,"Global\\Dvaia.PrivatePublication."+Hash(Utf8.GetBytes(user+"\n"+target.ToUpperInvariant())),out created,security);
   try {
    MutexSecurity actual=mutex.GetAccessControl();Require(((SecurityIdentifier)actual.GetOwner(typeof(SecurityIdentifier))).Value==user && actual.AreAccessRulesProtected);bool userFull=false;
    foreach(MutexAccessRule rule in actual.GetAccessRules(true,true,typeof(SecurityIdentifier))){string sid=((SecurityIdentifier)rule.IdentityReference).Value;Require(!rule.IsInherited && rule.AccessControlType==AccessControlType.Allow && (sid==user || sid==SystemSid) && rule.MutexRights==MutexRights.FullControl);if(sid==user)userFull=true;}
    Require(userFull);bool held;
    try{held=mutex.WaitOne(5000);}catch(AbandonedMutexException){held=true;}
    Require(held);return mutex;
   }catch{mutex.Dispose();throw;}
  }
  static string State(Scope scope,Intent intent,Opened target,Opened stage,Opened backup,Opened resultBackup,out byte[] resultBytes) {
   Require(resultBackup!=null);byte[] expectedResult=scope.Read(resultBackup);Require(Matches(resultBackup,intent.resultBackup,expectedResult));
   byte[] original=null;
   if(intent.originalBackup!=null){Require(backup!=null);original=scope.Read(backup);Require(Matches(backup,intent.originalBackup,original));}
   else Require(backup==null);
   if(target!=null){byte[] current=scope.Read(target);if(Matches(target,intent.result,current) && Equal(current,expectedResult)){Require(stage==null);resultBytes=current;return "committed";}
    Require(intent.originalTarget!=null && Matches(target,intent.originalTarget,current) && Equal(current,original));
   }else Require(intent.originalTarget==null);
   Require(stage!=null);resultBytes=scope.Read(stage);Require(Matches(stage,intent.result,resultBytes) && Equal(resultBytes,expectedResult));return "prepared";
  }
  public static Dictionary<string,object> Invoke(string operation,string inputTarget,string inputIntent,string id,string originalBase64,string resultBase64) {
   Require(operation=="preparePrivatePublication" || operation=="inspectPrivatePublication" || operation=="publishPrivatePublication");
   Require(id!=null && Regex.IsMatch(id,@"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$"));
   string targetPath=Normalize(inputTarget),intentPath=Normalize(inputIntent),stagePath=Normalize(targetPath+".dvaia-"+id+".stage"),originalPath=Normalize(intentPath+".original"),resultPath=Normalize(intentPath+".result");
   Require(new HashSet<string>(new string[]{targetPath,intentPath,stagePath,originalPath,resultPath},StringComparer.OrdinalIgnoreCase).Count==5);
   bool prepare=operation=="preparePrivatePublication";byte[] requestedOriginal=originalBase64==null?null:Decode(originalBase64),requestedResult=resultBase64==null?null:Decode(resultBase64);
   Require(prepare?requestedResult!=null:requestedOriginal==null && requestedResult==null);
   string user;using(WindowsIdentity identity=WindowsIdentity.GetCurrent())user=identity.User.Value;
   using(Mutex mutex=Locked(targetPath,user)) {
    try {
     using(Scope scope=new Scope(user)) {
      scope.Parents(targetPath,false);scope.Parents(intentPath,true);
      Opened retained=scope.Maybe(intentPath),target=scope.Maybe(targetPath),stage=scope.Maybe(stagePath),backup=scope.Maybe(originalPath),resultBackup=scope.Maybe(resultPath);Intent intent;byte[] intentBytes;
      if(retained==null) {
       Require(prepare);
       byte[] original=null;if(target!=null){original=scope.Read(target);Require(requestedOriginal!=null && Equal(original,requestedOriginal));}else Require(requestedOriginal==null);
       if(original==null)Require(backup==null);else {if(backup==null)backup=scope.Create(originalPath,original);else Require(Equal(scope.Read(backup),original));}
       if(resultBackup==null)resultBackup=scope.Create(resultPath,requestedResult);else Require(Equal(scope.Read(resultBackup),requestedResult));
       if(stage==null)stage=scope.Create(stagePath,requestedResult);else Require(Equal(scope.Read(stage),requestedResult));
       byte[] staged=scope.Read(stage);scope.Check();
       intent=new Intent{version=1,kind="windows-private-publication",userSid=user,operationId=id,targetPath=targetPath,intentPath=intentPath,stagePath=stagePath,originalPath=original==null?null:originalPath,resultPath=resultPath,originalTarget=target==null?null:Capture(target,original),originalBackup=backup==null?null:Capture(backup,scope.Read(backup)),result=Capture(stage,staged),resultBackup=Capture(resultBackup,scope.Read(resultBackup))};
       intentBytes=Encode(intent);Require(intentBytes.Length<=MaxBytes);retained=scope.Create(intentPath,intentBytes);
      } else {intentBytes=scope.Read(retained);intent=Parse(intentBytes,targetPath,intentPath,id,user);}
      byte[] resultBytes;string state=State(scope,intent,target,stage,backup,resultBackup,out resultBytes);
      if(prepare) {Require(Equal(resultBytes,requestedResult));if(intent.originalBackup==null)Require(requestedOriginal==null);else Require(requestedOriginal!=null && Equal(scope.Read(backup),requestedOriginal));}
      // A failed creation flush can leave complete readable bytes. Recovery
      // must re-establish their durability before callers use retained secrets.
      Require(FlushFileBuffers(resultBackup.Handle));
      if(backup!=null)Require(FlushFileBuffers(backup.Handle));
      Require(FlushFileBuffers((state=="prepared"?stage:target).Handle));
      Require(FlushFileBuffers(retained.Handle));
      scope.Check();Require(Equal(scope.Read(retained),intentBytes));
      if(operation=="publishPrivatePublication") {
       if(state=="prepared") {
        Require(stage.Before.Volume==(target==null?stage.Before.Volume:target.Before.Volume));
        // Validate exact old bytes again while its handle rejects write sharing.
        // Ancestor handles and the cross-session mutex remain continuously
        // held. Classic replacement can reject open target handles, so close
        // the verified private leaves only for the move. ACLs exclude other
        // identities from mutating these leaves; cooperating owner processes
        // wait for this same mutex. Arbitrary same-user mutation is excluded.
        if(target!=null)Require(Equal(scope.Read(target),scope.Read(backup)) && Matches(target,intent.originalTarget,scope.Read(target)));
        Require(Matches(stage,intent.result,scope.Read(stage)));Require(FlushFileBuffers(stage.Handle));
        scope.Check();stage.Dispose();if(target!=null)target.Dispose();
        Require(MoveFileExW(stagePath,targetPath,MoveWriteThrough|(intent.originalTarget==null?0:MoveReplaceExisting)));
        target=scope.Maybe(targetPath);Require(target!=null && Matches(target,intent.result,scope.Read(target)) && Equal(scope.Read(target),resultBytes));
        Require(FlushFileBuffers(target.Handle));state="committed";
       } else Require(FlushFileBuffers(target.Handle));
       Require(Matches(target,intent.result,scope.Read(target)));
      }
      scope.Check();Require(Equal(scope.Read(retained),intentBytes));
      return new Dictionary<string,object>{{"version",1},{"ok",true},{"operation",operation},{"targetPath",targetPath},{"intentPath",intentPath},{"operationId",id},{"state",state},{"intentSha256",Hash(intentBytes)},{"size",intent.result.size},{"identity",new Dictionary<string,object>{{"volumeSerial",intent.result.volumeSerial},{"fileId",intent.result.fileId}}}};
     }
    } finally {mutex.ReleaseMutex();}
   }
  }
 }
}

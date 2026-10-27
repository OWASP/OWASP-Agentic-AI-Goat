"""Fixed private pipe host for the V03 Listings listener; no arbitrary commands.

The owning Node driver must pin this complete source closure and conservatively
map its absolute phase endpoints against the initial bounded clock sample.
Local close never claims guest channel retirement.
"""
import json,os,re,select,sys,time
from v03_listings_bridge import V03ListingsBridge

CAP=16384
def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('V03_BRIDGE_DUPLICATE')
        value[key]=item
    return value

def read_frame(fd,deadline):
    data=bytearray()
    while True:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('V03_BRIDGE_PIPE_DEADLINE')
        ready,_,_=select.select([fd],[],[],remaining)
        if not ready:raise TimeoutError('V03_BRIDGE_PIPE_DEADLINE')
        part=os.read(fd,1)
        if not part:raise EOFError('V03_BRIDGE_PIPE_EOF')
        data.extend(part)
        if len(data)>CAP:raise ValueError('V03_BRIDGE_FRAME_BOUND')
        if part==b'\n':return json.loads(data,object_pairs_hook=unique)

def write_frame(fd,value):
    raw=(json.dumps(value,separators=(',',':'),allow_nan=False)+'\n').encode()
    if len(raw)>CAP:raise ValueError('V03_BRIDGE_FRAME_BOUND')
    deadline=time.monotonic()+2
    while raw:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('V03_BRIDGE_PIPE_WRITE')
        _,ready,_=select.select([],[fd],[],remaining)
        if not ready:raise TimeoutError('V03_BRIDGE_PIPE_WRITE')
        try:count=os.write(fd,raw)
        except BlockingIOError:continue
        if count<=0:raise IOError('V03_BRIDGE_PIPE_WRITE')
        raw=raw[count:]

class Host:
    def __init__(self,root,run,parent,plan,lease):
        self.root,self.run,self.parent,self.plan,self.lease=root,run,parent,plan,lease
        self.bridge=None;self.sequence=0;self.state='new';self.receipt=None;self.parent_deadline=None
        self.deadline=time.monotonic()+10
    def dispatch(self,request):
        if (type(request) is not dict or set(request)!={'version','runId','planSha256','sequence','op','payload'}
                or type(request['version']) is not int or request['version']!=1 or request['runId']!=self.run
                or request['planSha256']!=self.plan or type(request['sequence']) is not int
                or request['sequence']!=self.sequence or type(request['payload']) is not dict
                or time.monotonic()>=self.deadline):raise ValueError('V03_BRIDGE_REQUEST')
        op,data=request['op'],request['payload']
        if op=='start':
            if self.state!='new' or set(data)!={'startupDeadlineMs','parentDeadlineMs'} or any(type(data[k]) is not int for k in data):
                raise ValueError('V03_BRIDGE_START')
            end=data['startupDeadlineMs']/1000
            parent_end=data['parentDeadlineMs']/1000
            if not 0<end-time.monotonic()<=60 or not end<=parent_end<=time.monotonic()+11096:raise ValueError('V03_BRIDGE_START')
            self.deadline=end
            self.bridge=V03ListingsBridge(self.root,self.run,self.parent,self.plan,end,self.lease)
            result={'origin':self.bridge.open()};self.state='ready'
            # Reserve only: no acceptor runs before claim. MAIN setup can use
            # its original wrapper without spending the later cohort early.
            self.parent_deadline=parent_end;self.deadline=parent_end
        elif op=='claim':
            if self.state!='ready' or set(data)!={'handoff','hostDeadlineMs','activationDeadlineMs','guestRecord'}:
                raise ValueError('V03_BRIDGE_CLAIM')
            if any(type(data[k]) is not int for k in ('hostDeadlineMs','activationDeadlineMs')):
                raise ValueError('V03_BRIDGE_CLAIM')
            if data['hostDeadlineMs']/1000>self.parent_deadline:raise ValueError('V03_BRIDGE_PARENT_EXPIRY')
            self.bridge.claim(data['handoff'],host_deadline=data['hostDeadlineMs']/1000,
                activation_deadline=data['activationDeadlineMs']/1000,guest_record=data['guestRecord'])
            self.deadline=data['hostDeadlineMs']/1000;self.state='claimed';result={'claimed':True}
        elif op=='close':
            if data:raise ValueError('V03_BRIDGE_CLOSE')
            result=self.close()
        else:raise ValueError('V03_BRIDGE_OPERATION')
        self.sequence+=1
        return dict(version=1,runId=self.run,planSha256=self.plan,sequence=request['sequence'],op=op,result=result)
    def close(self):
        if self.receipt is not None:return self.receipt
        if self.bridge is None:
            self.receipt=dict(listenerClosed=True,localChannelsRetired=True,remoteChannelsVerified=False,
                channelIds=[],channelStates=[],failures=[])
        else:self.receipt=self.bridge.close(time.monotonic()+10)
        self.state='closed';return self.receipt

def main():
    if sys.platform!='darwin' or len(sys.argv)!=6:raise ValueError('V03_BRIDGE_HOST_PLATFORM')
    root,run,parent,plan,lease=sys.argv[1:]
    if os.path.realpath(root)!=root or any(not re.fullmatch('[a-f0-9]{'+str(n)+'}',s)
            for s,n in [(run,32),(parent,32),(plan,64),(lease,64)]):raise ValueError('V03_BRIDGE_HOST_BINDING')
    os.set_blocking(1,False)
    host=Host(root,run,parent,plan,lease);primary=None;receipt=None
    try:
        write_frame(1,dict(version=1,stage='hello',pid=os.getpid(),parentPid=os.getppid(),
            monotonicMs=time.monotonic_ns()//1000000,runId=run,planSha256=plan))
        while host.state!='closed':write_frame(1,host.dispatch(read_frame(0,host.deadline)))
    except BaseException as error:primary=error
    finally:
        try:receipt=host.close()
        except BaseException as error:primary=primary or error
        # Even EOF/expired lease triggers local close. Terminal proof contains
        # actual channel IDs/states; absence of this row is unresolved debt.
        write_frame(1,dict(version=1,stage='terminal',runId=run,planSha256=plan,
            failure=type(primary).__name__ if primary else None,local=receipt,
            cleanupDebt=primary is not None,
            leaseSourceCloseUnproven=bool(getattr(primary,'leaseSourceCloseUnproven',False))))
    if primary:raise primary

if __name__=='__main__':main()

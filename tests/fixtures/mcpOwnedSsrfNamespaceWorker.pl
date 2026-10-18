# Test-only final worker. Every privileged setup operation has already finished.
use strict; use warnings; use Socket; use IO::Socket::INET; use POSIX qw(:sys_wait_h);
my($arch,$outer_port)=@ARGV;
my($capget,$prctl)=$arch eq 'arm64'?(90,167):$arch eq 'x64'?(125,157):die "architecture\n";
my $header=pack('L L',0x20080522,0);my $caps=pack('L6',0,0,0,0,0,0);
syscall($capget,$header,$caps)==0 or die "capget:$!\n";
die "nonzero effective/permitted/inheritable caps\n" if grep {$_!=0} unpack('L6',$caps);
for my $cap(0..63){my $value=syscall($prctl,23,$cap,0,0,0);last if $value==-1&&$!{EINVAL};die "nonzero bounding set:$cap\n" unless $value==0;my $ambient=syscall($prctl,47,1,$cap,0,0);die "nonzero ambient set:$cap\n" unless $ambient==0;}
die "no_new_privs absent\n" unless syscall($prctl,39,0,0,0,0)==1;
my @executable=stat('/usr/bin/perl');die "unsafe worker executable\n" unless @executable && $executable[4]==65534 && !($executable[2]&06022);
die "host filesystem visible\n" if -e '/app/index.js';
die "resolver available\n" if -e '/etc/resolv.conf';
sub netlink_dump {
 my($type,$payload)=@_;socket(my $sock,16,SOCK_RAW,0) or die "netlink socket:$!\n";
 bind($sock,pack('S S L L',16,0,0,0)) or die "netlink bind:$!\n";
 my $request=pack('L S S L L',16+length($payload),$type,0x301,1,0).$payload;
 send($sock,$request,0,pack('S S L L',16,0,0,0)) or die "netlink send:$!\n";
 my @messages;
 while(1){my $buffer='';defined(recv($sock,$buffer,65536,0)) or die "netlink recv:$!\n";
  while(length($buffer)>=16){my($len,$kind)=unpack('L S',$buffer);die "netlink length\n" if $len<16||$len>length($buffer);
   if($kind==3){close($sock);return @messages;}die "netlink error\n" if $kind==2;
   push @messages,[$kind,substr($buffer,16,$len-16)];substr($buffer,0,($len+3)&~3,'');}
 }
}
sub attrs {my($bytes)=@_;my %result;while(length($bytes)>=4){my($len,$type)=unpack('S S',$bytes);die "attribute length\n" if $len<4||$len>length($bytes);$result{$type}=substr($bytes,4,$len-4);substr($bytes,0,($len+3)&~3,'');}return %result;}
my @links=netlink_dump(18,pack('C C S l L L',0,0,0,0,0,0));
my @names;for my $message(@links){my %a=attrs(substr($message->[1],16));my $name=$a{3}//'';$name=~s/\0.*//s;push @names,$name;}
die "external interface\n" unless @names==1&&$names[0] eq 'lo';
my @routes=netlink_dump(26,pack('C8 L',AF_INET,0,0,0,0,0,0,0,0));
for my $message(@routes){my @r=unpack('C8 L',$message->[1]);die "default route\n" if $r[1]==0&&$r[7]==1;}
my $server=IO::Socket::INET->new(LocalAddr=>'10.0.1.100',LocalPort=>8080,Listen=>1,ReuseAddr=>1,Proto=>'tcp') or die "listen:$!\n";
pipe(my $journal_read,my $journal_write) or die "pipe:$!\n";
my $pid=fork();defined($pid) or die "fork:$!\n";
if(!$pid){close($journal_read);alarm(8);my $client=$server->accept() or die "accept:$!\n";my $request='';while($request!~/\r\n\r\n/){my $chunk='';my $n=sysread($client,$chunk,1024);die "request read\n" unless $n;$request.=$chunk;die "request limit\n" if length($request)>4096;}
 print $client "HTTP/1.1 200 OK\r\nContent-Length: 22\r\nConnection: close\r\n\r\nowned-synthetic-canary\n";
 print $journal_write $client->sockhost()."\n".$request;close($client);close($journal_write);close($server);exit(0);}
close($journal_write);close($server);
my $error;
eval {
 # Raw selected URL drives the ordinary socket destination and request path.
 my $url='http://10.0.1.100:8080/probe?raw=preserved';
 $url=~m{\Ahttp://([^/:]+):(\d+)(/.*)\z} or die "URL\n";my($host,$port,$path)=($1,$2,$3);
 my $client=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$port,Proto=>'tcp',Timeout=>1) or die "connect:$!\n";
 print $client "GET $path HTTP/1.1\r\nHost: $host:$port\r\nConnection: close\r\n\r\n";
 my $response=do{local $/;<$client>};close($client);die "response mismatch\n" unless $response=~/owned-synthetic-canary\n\z/;
 my $receipt=do{local $/;<$journal_read>};die "socket mismatch\n" unless $receipt=~/\A10\.0\.1\.100\nGET \/probe\?raw=preserved HTTP\/1.1/;
 for my $destination(['127.0.0.1',$outer_port],['169.254.169.254',80],['10.99.99.99',8080],['1.1.1.1',80],['8.8.8.8',53]){my $socket=IO::Socket::INET->new(PeerAddr=>$destination->[0],PeerPort=>$destination->[1],Proto=>'tcp',Timeout=>1);die "egress unexpectedly reachable\n" if $socket;}
 waitpid($pid,0)==$pid or die "waitpid\n";die "server failed\n" if $?;
 print '{"prototypeOnly":true,"rawUrlSocketPassed":true,"zeroFinalCapabilities":true,"noDefaultRoute":true,"interfaces":["lo"],"negativeDestinations":5,"joinedServer":true,"metadataPort80Qualified":false}'."\n";
 1;
} or $error=$@;
if($error){kill('KILL',$pid);waitpid($pid,0);die $error;}

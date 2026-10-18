# Test-only namespace initializer. Never installed or selected by the application.
use strict;
use warnings;
use Socket;
my ($capset, $prctl) = $ARGV[0] eq 'arm64' ? (91,167) : $ARGV[0] eq 'x64' ? (126,157) : die "architecture\n";
my $getcaps = $ARGV[0] eq 'arm64' ? 90 : 125;
my $before_header=pack('L L',0x20080522,0);my $before_data=pack('L6',0,0,0,0,0,0);
syscall($getcaps,$before_header,$before_data)==0 or die "setup capget:$!\n";
print STDERR "setup_cap_words=".join(',',unpack('L6',$before_data))."\n";
socket(my $control, AF_INET, SOCK_DGRAM, 0) or die "socket:$!\n";
my $address = pack('a16 S n a4 x16', 'lo', AF_INET, 0, inet_aton('10.0.1.100'));
ioctl($control, 0x8916, $address) or die "SIOCSIFADDR:$!\n";
my $mask = pack('a16 S n a4 x16', 'lo', AF_INET, 0, inet_aton('255.255.255.255'));
ioctl($control, 0x891c, $mask) or die "SIOCSIFNETMASK:$!\n";
my $flags = pack('a16 S x22', 'lo', 9);
ioctl($control, 0x8914, $flags) or die "SIOCSIFFLAGS:$!\n";
close($control);
for my $cap (0..63) {
  my $present=syscall($prctl,23,$cap,0,0,0);
  last if $present==-1 && $!{EINVAL};
  die "bounding-read:$!\n" if $present<0;
  syscall($prctl,24,$cap,0,0,0)==0 or die "bounding-drop:$!\n";
}
syscall($prctl,47,4,0,0,0)==0 or die "ambient:$!\n";
my $header=pack('L L',0x20080522,0);my $data=pack('L6',0,0,0,0,0,0);
syscall($capset,$header,$data)==0 or die "capset:$!\n";
syscall($prctl,38,1,0,0,0)==0 or die "no_new_privs:$!\n";
exec('/usr/bin/perl','/tmp/ssrf-worker.pl',@ARGV) or die "exec:$!\n";

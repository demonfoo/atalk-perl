#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use IO::Socket::DDP;
use Net::Atalk;
use Net::Atalk::NBP;
use Time::HiRes qw(gettimeofday setitimer ITIMER_REAL time);
use Errno qw(EINTR);
use Getopt::Long;
use Readonly;

Readonly my $AEPOP_REQUEST  => 1;
Readonly my $AEPOP_REPLY    => 2;

use Carp ();
local $SIG{'__WARN__'} = \&Carp::cluck;

my $port = getservbyname('echo', 'ddp') || 4;

my ($msec_total, $msec_min, $msec_max, $sent, $rcvd, $dups) =
        (0, -1, -1, 0, 0, 0);
my $count       = 0;
my $interval    = 1.0;
my $print_stamp;
my $quiet;
my $timing;
my $datalen     = 32;
my %sockparms   = ('Proto' => 'ddp');
my $audible;

Getopt::Long::Configure('no_ignore_case');
GetOptions( 'c=i'   => \$count,
            'I=s'   => sub { $sockparms{'LocalAddr'} = $_[1] },
            'i=f'   => \$interval,
            'q'     => \$quiet,
            'D'     => \$print_stamp,
            's=i'   => \$datalen,
            'b'     => sub { $sockparms{'Broadcast'} = 1 },
            'a'     => \$audible,
            'h'     => \&usage ) || usage();

usage() unless scalar(@ARGV) == 1;

if ($datalen < 0) {
    print STDERR "Data size less than 0 is impossible\n";
    exit(1);
}

if ($datalen + length(pack('x[C]x[C]x[L!]')) > $DDP_MAXSZ) {
    print STDERR "Data size impossibly large for DDP\n";
    exit(1);
}

my ($target) = @ARGV;

my $paddr = atalk_aton($target);
unless (defined $paddr) {
    $target =~ s/(?::([\w\s\-]*|=))?(?:\@(\w*|\*))?$//;
    my ($type, $zone) = ($1, $2);
    my @tuples = NBPLookup($target, $type, $zone,
            exists $sockparms{'LocalAddr'} ? $sockparms{'LocalAddr'} : undef,
            1);
    unless (scalar(@tuples)) {
        printf(STDERR "Can't resolve \"\%s\"\n", $target);
        exit(1);
    }
    $target = $tuples[0][0];
    $paddr = atalk_aton($target);
}
my $sock = new IO::Socket::DDP(%sockparms) or die "Can't bind: $@";
my $dest = pack_sockaddr_at($port, $paddr);

my $stamplen = length(pack('x[L!]x[L!]'));
if ($datalen >= $stamplen) {
    $timing = 1;
}

sub usage {
    print "usage:\t", $0,
            " [-abDq] [-I source address] [-i interval] \n\t\t",
            "[-c count] [-s size] ( addr | nbpname )\n";
    exit(1);
}

sub send_echo {
    # Declare $! as local so error codes in this context don't leak out.
    local $!;
    my $trailer = "\0" x $datalen;
    if ($timing) {
        substr($trailer, 0, $stamplen, pack('L!L!', gettimeofday()));
    }
    my $msg = pack('CCL!a*', $DDPTYPE_AEP, $AEPOP_REQUEST, $sent++, $trailer);
    die "send() failed: $!" unless defined send($sock, $msg, 0, $dest);
    if ($count && $sent > $count) { finish() }
    $SIG{'ALRM'} = \&send_echo;
}

sub finish {
    if ($sent) {
        printf("\n---- \%s AEP Statistics ----\n", $target);
        printf("\%d packets sent, \%d packets received\%s, \%d\%\% packet loss\n",
             $sent, $rcvd, $dups ? sprintf(', +%u duplicates', $dups) : '',
             ($sent - $rcvd) * 100 / $sent);
        if ($rcvd && $timing) {
            printf("round trip (msec) min/avg/max: \%.3f/\%.3f/\%.3f\n",
                $msec_min, $msec_total / ($rcvd + $dups), $msec_max);
        }
    }
    exit($rcvd < 1);
}

sub status {
    if ($sent) {
        printf(STDERR "\r\%d/\%d packets, \%d\%\% loss",
                $sent, $rcvd, ($sent - $rcvd) * 100 / $sent);
        printf(STDERR ', min/avg/max = %.3f/%.3f/%.3f ms', $msec_min,
                $msec_total / ($rcvd + $dups), $msec_max) if $timing;
        print STDERR "\n";
    }
    $SIG{'QUIT'} = \&status;
}

$SIG{'INT'}     = \&finish;
$SIG{'ALRM'}    = \&send_echo;
$SIG{'QUIT'}    = \&status;

setitimer(ITIMER_REAL, $interval, $interval);

while (1) {
    my $rbuf;
    my $from = recv($sock, $rbuf, $DDP_MAXSZ, 0);
    unless (defined $from) {
        next if $! == EINTR;
        die "recv failed: $!";
    }
    if ($rcvd < $sent) { $rcvd++ } else { $dups++ }
    my ($ddptype, $aeptype, $seqno, $trailer) =
         unpack('CCL!a*', $rbuf);
    my $delta;
    if ($timing) {
        my ($now_sec, $now_usec) = gettimeofday();
        my ($t_sec, $t_usec) = unpack('L!L!', $trailer);
        $delta = ($now_sec - $t_sec) * 1000 + ($now_usec - $t_usec) / 1000;
        $msec_total += $delta;
        if ($delta > $msec_max) { $msec_max = $delta }
        if ($delta < $msec_min || $msec_min == -1) { $msec_min = $delta }
    }
    my $haddr = atalk_ntoa( (unpack_sockaddr_at($from))[1] );
    unless ($quiet) {
        printf('[%f] ', time()) if $print_stamp;
        printf('%d bytes from %s: aep_seq=%d', length($rbuf), $haddr, $seqno);
        printf(', %.3f msec', $delta) if $timing;
        print "\a" if $audible;
        print "\n";
    }
    if ($count && $seqno + 1 >= $count) { finish() }
}

# vim: ts=4 et ai

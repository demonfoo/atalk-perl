package Net::Atalk;

use Exporter qw(import);
use Socket;                 # for AF_APPLETALK
use English qw(-no_match_vars);
use Readonly;

use strict;
use warnings;
use diagnostics;

our @EXPORT = qw(atalk_aton atalk_ntoa pack_sockaddr_at unpack_sockaddr_at
                 sockaddr_at $DDPTYPE_RTMPRD $DDPTYPE_NBP $DDPTYPE_ATP
                 $DDPTYPE_AEP $DDPTYPE_RTMPR $DDPTYPE_ZIP $DDPTYPE_ADSP
                 $ATPORT_FIRST $ATADDR_ANY $ATPORT_RESERVED $ATPORT_LAST
                 $ATADDR_ANYNET $ATADDR_ANYNODE $ATADDR_ANYPORT $ATADDR_BCAST
                 $DDP_MAXSZ $DDP_MAXHOPS);

Readonly our $DDPTYPE_RTMPRD     => 1;  # RTMP response/data
Readonly our $DDPTYPE_NBP        => 2;
Readonly our $DDPTYPE_ATP        => 3;
Readonly our $DDPTYPE_AEP        => 4;
Readonly our $DDPTYPE_RTMPR      => 5;  # RTMP request
Readonly our $DDPTYPE_ZIP        => 6;
Readonly our $DDPTYPE_ADSP       => 7;

Readonly our $ATPORT_FIRST       => 1;
Readonly our $ATPORT_RESERVED    => 128;
Readonly our $ATPORT_LAST        => 254; # only legal on localtalk
Readonly our $ATADDR_ANYNET      => 0;
Readonly our $ATADDR_ANYNODE     => 0;
Readonly our $ATADDR_ANYPORT     => 0;
Readonly our $DDP_MAXSZ          => 587;
Readonly our $DDP_MAXHOPS        => 15; # 4 bit hop counter

sub atalk_aton {
    my($addr) = @_;

    my($net, $node) = $addr =~ m{^
                                  (\d{1,5})     # match net number
                                  [.]           # separator char
                                  (\d{1,3})     # match node number
                                 $}sx;
    return if not(defined $net or defined $node);
    return pack 'nCx', $net, $node;
}

Readonly our $ATADDR_ANY         => atalk_aton('0.0');
Readonly our $ATADDR_BCAST       => atalk_aton('0.255');

sub atalk_ntoa {
    my($paddr) = @_;

    return sprintf '%d.%d', unpack 'nC', $paddr;
}

sub sockaddr_at {
    if (scalar(@_) == 1) {
        return unpack_sockaddr_at(@_);
    } else {
        return pack_sockaddr_at(@_);
    }
}

sub pack_sockaddr_at {
    my($port, $paddr) = @_;

    my @arglist = (AF_APPLETALK, $port, $paddr);
    if ($OSNAME ne 'linux') { unshift @arglist, 16; }
    # On *BSD, the first byte of sockaddr structs is a byte to indicate
    # the size of the struct. Linux doesn't do this.
    return pack $OSNAME eq 'linux' ? 'SCxa[4]x[8]' : 'CCCxa[4]x[8]', @arglist;
}

sub unpack_sockaddr_at {
    my($psock) = @_;

    return unpack 'x[2]Cxa[4]x[8]', $psock;
}
1;
# vim: ts=4 ai et

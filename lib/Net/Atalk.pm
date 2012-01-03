package Net::Atalk;

use Exporter qw(import);
use Socket;                 # for AF_APPLETALK

use strict;
use warnings;

our @EXPORT = qw(atalk_aton atalk_ntoa pack_sockaddr_at unpack_sockaddr_at
                 sockaddr_at DDPTYPE_RTMPRD DDPTYPE_NBP DDPTYPE_ATP DDPTYPE_AEP
                 DDPTYPE_RTMPR DDPTYPE_ZIP DDPTYPE_ADSP ATPORT_FIRST ATADDR_ANY
                 ATPORT_RESERVED ATPORT_LAST ATADDR_ANYNET ATADDR_ANYNODE
                 ATADDR_ANYPORT ATADDR_BCAST DDP_MAXSZ DDP_MAXHOPS);

use constant DDPTYPE_RTMPRD     => 1;	# RTMP response/data
use constant DDPTYPE_NBP        => 2;
use constant DDPTYPE_ATP        => 3;
use constant DDPTYPE_AEP        => 4;
use constant DDPTYPE_RTMPR      => 5;	# RTMP request
use constant DDPTYPE_ZIP        => 6;
use constant DDPTYPE_ADSP       => 7;

use constant ATPORT_FIRST       => 1;
use constant ATPORT_RESERVED    => 128;
use constant ATPORT_LAST        => 254; # only legal on localtalk
use constant ATADDR_ANYNET      => 0;
use constant ATADDR_ANYNODE     => 0;
use constant ATADDR_ANYPORT     => 0;
use constant DDP_MAXSZ          => 587;
use constant DDP_MAXHOPS        => 15; # 4 bit hop counter

sub atalk_aton {
    my($addr) = @_;

    my($net, $node) = $addr =~ /^(\d{1,5})\.(\d{1,3})$/;
    return unless defined $net && defined $node;
    return pack('nCx', $net, $node);
}

use constant ATADDR_ANY         => atalk_aton('0.0');
use constant ATADDR_BCAST       => atalk_aton('0.255');

sub atalk_ntoa {
    my($paddr) = @_;

    return sprintf('%d.%d', unpack('nC', $paddr));
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
    if ($^O ne 'linux') { unshift(@arglist, 16); }
    # On *BSD, the first byte of sockaddr structs is a byte to indicate
    # the size of the struct. Linux doesn't do this.
    return pack($^O eq 'linux' ? 'SCxa[4]x[8]' : 'CCCxa[4]x[8]', @arglist);
}

sub unpack_sockaddr_at {
    my($psock) = @_;

    return unpack('x[2]Cxa[4]x[8]', $psock);
}
1;
# vim: ts=4 ai et

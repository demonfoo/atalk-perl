package Net::Atalk::NBP;

use IO::Socket::DDP;
use Net::Atalk;
use IO::Poll qw(POLLIN);
use Time::HiRes qw(gettimeofday);
use Readonly;
use English qw(-no_match_vars);

use strict;
use warnings;
use diagnostics;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{'__WARN__'} = \&Carp::cluck;

use Exporter qw(import);

our @EXPORT = qw($NBP_BrRq $NBP_FwdReq NBPLookup);

Readonly our $NBP_BrRq       => 1;
Readonly my  $NBP_LkUp       => 2;
Readonly my  $NBP_LkUp_Reply => 3;
Readonly our $NBP_FwdReq     => 4;

our $id = 1;

# Construct an NBP packet.
sub AssemblePacket {
    my ($Function, $ID, @Tuples) = @_;

    croak("Can't have more than 15 tuples") if scalar(@Tuples) > 15;
    return(pack('CCC', $DDPTYPE_NBP,
                (($Function & 0x0f) << 4) | scalar(@Tuples), $ID) .
                join(q{}, map { AssembleTuple(@{$_}) } @Tuples));
}

# Construct an NBP singleton tuple.
sub AssembleTuple {
    my ($NodeAddr, $SockNo, $Enumerator, $Object, $Type, $Zone) = @_;

    return pack('a[3]CCC/aC/aC/a', atalk_aton($NodeAddr), $SockNo,
            $Enumerator, $Object, $Type, $Zone);
}

# Unpack an NBP packet into its constituent fields.
sub UnpackPacket {
    my ($packet) = @_;

    my ($pkttype, $fn_cnt, $ID, $tupledata) = unpack('CCCa*', $packet);
    return if $pkttype != $DDPTYPE_NBP;
    my $Function = ($fn_cnt >> 4) & 0x0F;
    my $tuplecount = $fn_cnt & 0x0F;
    return($Function, $ID, UnpackTuples($tuplecount, $tupledata));
}

# Unpack a packed set of NBP record tuples.
sub UnpackTuples {
    my ($tuplecount, $tupledata) = @_;

    my @tuple_data = unpack('a[3]CCC/aC/aC/a' x $tuplecount, $tupledata);
    my @tuples;
    foreach my $i (0 .. ($tuplecount - 1)) {
        my @tuple = @tuple_data[ ($i * 6) .. (($i * 6) + 5) ];
        $tuple[0] = atalk_ntoa($tuple[0]);
        push(@tuples, [ @tuple ]);
    }
    return(@tuples);
}

sub NBPLookup {
    my($Obj, $Type, $Zone, $FromAddr, $maxresps) = @_;

    # Bind a local, broadcast-capable socket for sending out NBP
    # packets from (and receiving responses).
    my %sockparms = ( 'Proto'       => 'ddp',
                      'Broadcast'   => 1 );
    if (defined $FromAddr) { $sockparms{'LocalAddr'} = $FromAddr }
    my $sock = IO::Socket::DDP->new(%sockparms) || croak $ERRNO;
    croak(q{Can't get local socket address, possibly atalk stack out of order})
            if not defined $sock->sockhost();

    # If the lookup properties are undef (or empty strings), assume
    # wildcards were intended.
    if (!defined $Obj || $Obj eq q{}) { $Obj = q{=} }
    if (!defined $Type || $Type eq q{}) { $Type = q{=} }
    if (!defined $Zone || $Zone eq q{}) { $Zone = q{*} }

    # Construct a lookup packet with a single tuple, requesting the given
    # entity name, service type and zone.
    my $packet = AssemblePacket($NBP_LkUp, $id++,
            [ $sock->sockhost(), $sock->sockport(), 0, $Obj, $Type, $Zone ]);

    # Try to look up the DDP port number for NBP; use the default if we
    # can't.
    my $port = getservbyname('nbp', 'ddp') || 2;

    # Pack a sockaddr_at for the broadcast address with the port number we
    # get above.
    my $dest = pack_sockaddr_at($port, $ATADDR_BCAST);

    my %rset;
    my @records;
RETRY:
    foreach my $tries (reverse(1 .. 3)) {
        # Send the query packet to the global broadcast address.
        send($sock, $packet, 0, $dest);

        # Set up a poll() object to check the socket for incoming packets.
        my $poll = IO::Poll->new();
        $poll->mask($sock, POLLIN);

        my $timeout = 2.0;
        while (1) {
            my ($s_sec, $s_usec) = gettimeofday();
            # Poll the socket for traffic, and retry the whole damn thing
            # if we don't see anything at all.
            next RETRY if not $poll->poll($timeout);
            my ($e_sec, $e_usec) = gettimeofday();
            # Compute how long it took us to poll the socket.
            $timeout -= ($e_sec - $s_sec) + (($e_usec - $s_usec) / 1000000);

            # Read in the packet on the socket.
            my $rbuf;
            return if not defined recv($sock, $rbuf, $DDP_MAXSZ, 0);

            # Unpack the NBP packet.
            my ($fn, $r_id, @tuples) = UnpackPacket($rbuf);

            # If the packet wasn't a lookup-reply packet (or an NBP packet,
            # if $fn is undef), just ignore it.
            next if not(defined $fn) or $fn != $NBP_LkUp_Reply;

            # Do some duplicate checking, then add the tuples to the set
            # to be returned to the caller.
            foreach my $tuple (@tuples) {
                my $key = join(q{|}, @{$tuple}[3,4]);
                next if exists $rset{$key};
                $rset{$key} = $tuple;
                push(@records, $tuple);
                last RETRY if $maxresps and scalar(@records) >= $maxresps;
            }
        }
    }

    return(@records);
}
1;

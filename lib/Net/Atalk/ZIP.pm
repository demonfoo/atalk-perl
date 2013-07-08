package Net::Atalk::ZIP;

use strict;
use warnings;
use diagnostics;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

use IO::Socket::DDP;
use Net::Atalk;
use Net::Atalk::ATP;
use IO::Poll qw(POLLIN);
use POSIX qw(ETIMEDOUT);
use Exporter qw(import);
use Readonly;
use English qw(-no_match_vars);

Readonly my $ZIP_Query_Req          => 1;
Readonly my $ZIP_Query_Resp         => 2;
Readonly my $ZIP_Query_RespExt      => 8;
Readonly my $ZIP_GetNetInfo_Req     => 5;
Readonly my $ZIP_GetNetInfo_Resp    => 6;
Readonly my $ZIP_ATP_GetMyZone      => 7;
Readonly my $ZIP_ATP_GetZoneList    => 8;
Readonly my $ZIP_ATP_GetLocalZones  => 9;

Readonly my $ZIP_GNI_ZoneInvalid    => 0x80;
Readonly my $ZIP_GNI_UseBroadcast   => 0x40;
Readonly my $ZIP_GNI_OnlyOneZone    => 0x20;

our @EXPORT = qw(ZIPQuery ZIPGetZoneList ZIPGetLocalZones ZIPGetMyZone
        ZIPGetNetInfo);

sub ZIPQuery {
    my (@netnums) = @_;

    my $port = getservbyname('zip', 'ddp') || 6;
    # Bind a local, broadcast-capable socket for sending out ZIP
    # packets from (and receiving responses).
    my %sockparms = ( Proto     => 'ddp',
                      Broadcast => 1 );
    my $sock = IO::Socket::DDP->new(%sockparms) || croak $ERRNO;
    croak("Can't get local socket address, possibly atalk stack out of order")
            if not defined $sock->sockhost();

    my $dest = pack_sockaddr_at($port, $ATADDR_BCAST);
    my $msg = pack('CCC/n*', $DDPTYPE_ZIP, $ZIP_Query_Req, @netnums);
    send($sock, $msg, 0, $dest);

    my $zonemap = {};
    my $poll = IO::Poll->new();
    $poll->mask($sock, POLLIN);
    return if not $poll->poll(2);
    my $rbuf;
    my $from = recv($sock, $rbuf, $DDP_MAXSZ, 0);
    return if not defined $from;
    my ($ddptype, $ziptype) = unpack('CC', $rbuf);
    return if $ddptype != $DDPTYPE_ZIP;
    return if $ziptype != $ZIP_Query_Resp &&
            $ziptype != $ZIP_Query_RespExt;
    my @data = unpack('xxC/(nC/a*)', $rbuf);
    my %namedata;
    while (scalar(@data)) {
        my $zonenum = shift(@data);
        my $zonename = shift(@data);
        if (!exists $namedata{$zonenum}) { $namedata{$zonenum} = [] }
        push(@{$namedata{$zonenum}}, $zonename);
    }

    return { %namedata };
}

sub ZIPGetZoneList {
    my ($FromAddr, $StartIndex) = @_;
    my %sockopts;
    if ($FromAddr) { $sockopts{LocalAddr} = $FromAddr }
    my $conn = Net::Atalk::ATP->new(%sockopts);
    return if not defined $conn;

    my $port = getservbyname('zip', 'ddp') || 6;
    my $dest = pack_sockaddr_at($port, $ATADDR_ANY);

    my $user_bytes = pack('Cxn', $ZIP_ATP_GetZoneList, $StartIndex);
    my $rdata;
    my $success;
    my $sem = $conn->SendTransaction(
        UserBytes       => $user_bytes,
        ResponseLength  => 1,
        ResponseStore   => \$rdata,
        StatusStore     => \$success,
        Timeout         => 2,
        NumTries        => 5,
        PeerAddr        => $dest,
    );
    # block on the semaphore until the thread tells us we're done
    $sem->down();
    $conn->close();
    if ($success) {
        my ($LastFlag, $count) = unpack('Cxn', $rdata->[0][0]);
        my @zonenames = unpack('C/a*' x $count, $rdata->[0][1]);
        return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
    }
    $ERRNO = ETIMEDOUT;
    return;
}

sub ZIPGetLocalZones {
    my ($FromAddr, $StartIndex) = @_;
    my %sockopts;
    if ($FromAddr) { $sockopts{LocalAddr} = $FromAddr }
    my $conn = Net::Atalk::ATP->new(%sockopts);
    return if not defined $conn;

    my $port = getservbyname('zip', 'ddp') || 6;
    my $dest = pack_sockaddr_at($port, $ATADDR_ANY);

    my $user_bytes = pack('Cxn', $ZIP_ATP_GetLocalZones, $StartIndex);
    my $rdata;
    my $success;
    my $sem = $conn->SendTransaction(
        UserBytes       => $user_bytes,
        ResponseLength  => 1,
        ResponseStore   => \$rdata,
        StatusStore     => \$success,
        Timeout         => 2,
        NumTries        => 5,
        PeerAddr        => $dest,
    );
    # block on the semaphore until the thread tells us we're done
    $sem->down();
    $conn->close();
    if ($success) {
        my ($LastFlag, $count) = unpack('Cxn', $rdata->[0][0]);
        my @zonenames = unpack('C/a*' x $count, $rdata->[0][1]);
        return wantarray() ? ([@zonenames], $LastFlag) : [@zonenames];
    }
    $ERRNO = ETIMEDOUT;
    return;
}

sub ZIPGetMyZone {
    my ($FromAddr) = @_;
    my %sockopts;
    if ($FromAddr) { $sockopts{LocalAddr} = $FromAddr }
    my $conn = Net::Atalk::ATP->new(%sockopts);
    return if not defined $conn;

    my $port = getservbyname('zip', 'ddp') || 6;
    my $dest = pack_sockaddr_at($port, $ATADDR_ANY);

    my $user_bytes = pack('Cxn', $ZIP_ATP_GetMyZone, 0);
    my $rdata;
    my $success;
    my $sem = $conn->SendTransaction(
        UserBytes       => $user_bytes,
        ResponseLength  => 1,
        ResponseStore   => \$rdata,
        StatusStore     => \$success,
        Timeout         => 2,
        NumTries        => 5,
        PeerAddr        => $dest,
    );
    # block on the semaphore until the thread tells us we're done
    $sem->down();
    $conn->close();
    if ($success) {
        my ($count) = unpack('xxn', $rdata->[0][0]);
        croak() if $count != 1;
        my ($zonename) = unpack('C/a*', $rdata->[0][1]);
        return $zonename;
    }
    $ERRNO = ETIMEDOUT;
    return;
}

sub ZIPGetNetInfo {
    my ($zonename) = @_;

    my $port = getservbyname('zip', 'ddp') || 6;
    # Bind a local, broadcast-capable socket for sending out ZIP
    # packets from (and receiving responses).
    my %sockparms = ( Proto     => 'ddp',
                      Broadcast => 1 );
    my $sock = IO::Socket::DDP->new(%sockparms) || croak $ERRNO;
    croak("Can't get local socket address, possibly atalk stack out of order")
            if not defined $sock->sockhost();

    my $dest = pack_sockaddr_at($port, $ATADDR_BCAST);
    my $msg = pack('CCx[5]C/a*', $DDPTYPE_ZIP, $ZIP_GetNetInfo_Req, $zonename);
    send($sock, $msg, 0, $dest);

    my $poll = IO::Poll->new();
    $poll->mask($sock, POLLIN);
    return if not $poll->poll(2);
    my $rbuf;
    my $from = recv($sock, $rbuf, $DDP_MAXSZ, 0);
    return if not defined $from;
    my ($ddptype, $ziptype) = unpack('CC', $rbuf);
    return if $ddptype != $DDPTYPE_ZIP;
    return if $ziptype != $ZIP_GetNetInfo_Resp;
    my (%zoneinfo, $extra, $flags);
    ($flags, @zoneinfo{'NetNum_start', 'NetNum_end', 'zonename', 'mcastaddr'},
            $extra) = unpack('xxCnnC/a*C/a*a*', $rbuf);
    $zoneinfo{mcastaddr} = join(q{:},
            unpack('H[2]' x 6, $zoneinfo{mcastaddr}));
    if ($flags & $ZIP_GNI_ZoneInvalid) {
        ($zoneinfo{default_zonename}) = unpack('C/a*', $extra);
    }
    $zoneinfo{ZoneInvalid}  = ($flags & $ZIP_GNI_ZoneInvalid) ? 1 : 0;
    $zoneinfo{UseBroadcast} = ($flags & $ZIP_GNI_UseBroadcast) ? 1 : 0;
    $zoneinfo{OnlyOneZone}  = ($flags & $ZIP_GNI_OnlyOneZone) ? 1 : 0;

    return { %zoneinfo };
}

1;
# vim: ts=4 ai fdm=marker

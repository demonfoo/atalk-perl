# This is Net::Atalk::ASP. It implements (mostly correctly) the ASP
# (AppleTalk Session Protocol) layer of the AppleTalk protocol family.
# It has a programming interface similar to Net::DSI; DSI was designed
# to layer over TCP/IP in a similar request/response fashion to ASP.
package Net::Atalk::ASP;

use Net::Atalk::ATP;
use Net::Atalk;         # for pack_sockaddr_at, unpack_sockaddr_at, atalk_aton
use threads::shared;    # for share
use strict;
use warnings;
use diagnostics;
use Readonly;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{'__WARN__'} = \&Carp::cluck;

Readonly my $SP_VERSION             => 0x0100;

Readonly my $OP_SP_CLOSESESS        => 1;
Readonly my $OP_SP_COMMAND          => 2;
Readonly my $OP_SP_GETSTATUS        => 3;
Readonly my $OP_SP_OPENSESS         => 4;
Readonly my $OP_SP_TICKLE           => 5;
Readonly my $OP_SP_WRITE            => 6;
Readonly my $OP_SP_WRITECONTINUE    => 7;
Readonly my $OP_SP_ATTENTION        => 8;

Readonly my $SP_TIMEOUT             => 120;

sub new { # {{{1
    my ($class, $host, $port) = @_;

    my $obj = bless {}, $class;
    $obj->{'atpsess'}       = Net::Atalk::ATP->new();
    return if not defined $obj->{'atpsess'};
    $obj->{'host'}          = $host;
    $obj->{'svcport'}       = $port;
    $obj->{'last_tickle'}   = undef;

    return $obj;
} # }}}1

sub _TickleFilter { # {{{1
    my ($realport, $lt_ref, $RqCB) = @_;
    my ($txtype)            = unpack('C', $RqCB->{'userbytes'});
    my ($portno, $paddr)    = unpack_sockaddr_at($RqCB->{'sockaddr'});

    if ($txtype == $OP_SP_TICKLE && $portno == $realport) {
        ${$lt_ref} = time();
        return [];
    }
    return;
} # }}}1

sub _TickleCheck { # {{{1
    my ($lt_ref, $time, $shared) = @_;

    if (${$lt_ref} + $SP_TIMEOUT < $time) {
        print "no tickle in more than timeout period, setting exit flag\n";
        $shared->{'exit'} = 1;
    }
    return;
} # }}}1

sub _AttnFilter { # {{{1
    my ($sid, $attnq_r, $realport, $RqCB) = @_;
    my ($txtype, $sessid, $attncode) = unpack('CCn', $RqCB->{'userbytes'});
    my ($portno, $paddr)             = unpack_sockaddr_at($RqCB->{'sockaddr'});

    if ($txtype == $OP_SP_ATTENTION && $sessid == $sid
            && $realport == $portno) {
        push(@{$attnq_r}, $attncode);
        return [ { 'userbytes' => pack('x[4]'), 'data' => q{}} ];
    }
    return;
} # }}}1

sub _CloseFilter { # {{{1
    my ($sid, $shared, $realport, $RqCB) = @_;
    my ($txtype, $sessid)   = unpack('CCx[2]', $RqCB->{'userbytes'});
    my ($portno, $paddr)    = unpack_sockaddr_at($RqCB->{'sockaddr'});

    if ($txtype == $OP_SP_CLOSESESS && $sessid == $sid
            && $realport == $portno) {
        $shared->{'exit'} = 1;
        return [ { 'userbytes' => pack('x[4]'), 'data' => q{}} ];
    }
    return;
} # }}}1

sub close { # {{{1
    my ($self) = @_;

    $self->{'atpsess'}->close();
    return;
} # }}}1

# Apparently this just returns these fixed values always...
sub SPGetParms { # {{{1
    my ($self, $resp_r) = @_;

    ${$resp_r} = {
                   'MaxCmdSize'     => $ATP_MAXLEN,
                   'QuantumSize'    => $ATP_MAXLEN * 8,
                 };

    return $kASPNoError;
} # }}}1

sub SPGetStatus { # {{{1
    my ($self, $resp_r) = @_;

    croak('$resp_r must be a scalar ref')
            if ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF';

    my ($rdata, $success);
    my $msg = pack('Cx[3]', $OP_SP_GETSTATUS);
    my $sa  = pack_sockaddr_at($self->{'svcport'}, atalk_aton($self->{'host'}));
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $msg,
        'ResponseLength'    => 1,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 2,
        'NumTries'          => 3,
        'PeerAddr'          => $sa,
    );
    return $sem if not ref($sem);
    $sem->down();
    if (!$success) { return $kASPNoServers; }
    ${$resp_r} = $rdata->[0][1];
    print '$kASPNoError is ', $kASPNoError, "\n";
    return $kASPNoError;
} # }}}1

sub SPOpenSession { # {{{1
    my ($self) = @_;

    my $wss = $self->{'atpsess'}->sockport();
    my $msg = pack('CCn', $OP_SP_OPENSESS, $wss, $SP_VERSION);
    my $sa  = pack_sockaddr_at($self->{'svcport'}, atalk_aton($self->{'host'}));
    my ($rdata, $success);
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $msg,
        'ResponseLength'    => 1,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 2,
        'NumTries'          => 3,
        'PeerAddr'          => $sa,
        'ExactlyOnce'       => $ATP_TREL_30SEC,
    );
    return $sem if not ref($sem);
    $sem->down();
    if (!$success) { return $kASPNoServers; }
    my ($srv_sockno, $sessionid, $errno)    = unpack('CCn', $rdata->[0][0]);
    @{$self}{'sessport', 'sessionid'}       = ($srv_sockno, $sessionid);
    $self->{'seqno'}                        = 0;
    $errno                                  = unpack('s', pack('S', $errno));
    if ($errno == $kASPNoError) { # {{{2
        # This will cause the client code to send an SPTickle, and resend
        # it every 30 seconds, forever. The server never actually sends
        # back a "response" to the pending transaction, thus forcing the
        # tickle request to keep going automatically, with no extra additions
        # required to the thread.
        $self->SPTickle(30, -1);

        # Handle incoming Attention requests.
        $self->{'attnq'}    = &share([]);
        my $filter          = &share([]);
        @{$filter}          = ( __PACKAGE__ . '::_AttnFilter',
                                $self->{'sessionid'}, $self->{'attnq'},
                                $self->{'sessport'} );
        $self->{'atpsess'}->AddTransactionFilter($filter);
        # Handle CloseSession requests from the server.
        $filter             = &share([]);
        @{$filter}          = ( __PACKAGE__ . '::_CloseFilter',
                                $self->{'sessionid'},
                                $self->{'atpsess'}{'Shared'},
                                $self->{'sessport'});
        $self->{'atpsess'}->AddTransactionFilter($filter);

        my $lt_ref          = \$self->{'last_tickle'};
        share($lt_ref);
        ${$lt_ref}          = time();

        $filter             = &share([]);
        # We have to pass the fully qualified subroutine name because we can't
        # pass subroutine refs from thread to thread.
        @{$filter}          = ( __PACKAGE__ . '::_TickleFilter',
                                $self->{'sessport'}, $lt_ref );
        $self->{'atpsess'}->AddTransactionFilter($filter);
        my $cb              = &share([]);
        @{$cb}              = ( __PACKAGE__ . '::_TickleCheck', $lt_ref );
        $self->{'atpsess'}->AddPeriodicCallback(5, $cb);
    } # }}}2
    return $errno;
} # }}}1

sub SPCloseSession { # {{{1
    my ($self) = @_;

    my $msg = pack('CCx[2]', $OP_SP_CLOSESESS, $self->{'sessionid'});
    my $sa = pack_sockaddr_at($self->{'sessport'} , atalk_aton($self->{'host'}));
    my ($rdata, $success);
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $msg,
        'ResponseLength'    => 1,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 1,
        'NumTries'          => 1,
        'PeerAddr'          => $sa,
    );
    delete $self->{'sessionid'};
    return $kASPNoError;
} # }}}1

sub SPCommand { # {{{1
    my ($self, $message, $resp_r) = @_;

    $resp_r = defined($resp_r) ? $resp_r : *foo{SCALAR};

    my $seqno = $self->{'seqno'}++ % (2 ** 16);
    # this will take an ATP_MSGLEN sized chunk of the message data and
    # send it to the server, to be processed as part of the request.
    my $ub = pack('CCn', $OP_SP_COMMAND, $self->{'sessionid'}, $seqno);
    my $sa = pack_sockaddr_at($self->{'sessport'} , atalk_aton($self->{'host'}));
    my ($rdata, $success);
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $ub,
        'Data'              => $message,
        'ResponseLength'    => 8,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 5,
        'PeerAddr'          => $sa,
        'ExactlyOnce'       => $ATP_TREL_30SEC
    );
    return $sem if not ref($sem);
    $sem->down();
    if (!$success) { return $kASPNoServers; }
    # string the response bodies back together
    ${$resp_r} = join(q{}, map { $_->[1]; } @{$rdata});
    # user bytes from the first response packet are the only ones that
    # are relevant...
    my ($errno) = unpack('l>', $rdata->[0][0]);
    return $errno;
} # }}}1

sub SPWrite { # {{{1
    my ($self, $message, $data_r, $d_len, $resp_r) = @_;

    croak('$resp_r must be a scalar ref')
            if ref($resp_r) ne 'SCALAR' and ref($resp_r) ne 'REF';
    croak('$data_r must be a scalar ref')
            if ref($data_r) ne 'SCALAR' and ref($data_r) ne 'REF';
    $d_len ||= length(${$data_r});

    my $seqno = $self->{'seqno'}++ % (2 ** 16);
    # this will take an ATP_MSGLEN sized chunk of the message data and
    # send it to the server, to be processed as part of the request.
    my $ub = pack('CCn', $OP_SP_WRITE, $self->{'sessionid'}, $seqno);
    my $sa = pack_sockaddr_at($self->{'sessport'} , atalk_aton($self->{'host'}));
    my ($rdata, $success);
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $ub,
        'Data'              => $message,
        'ResponseLength'    => 1,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 5,
        'PeerAddr'          => $sa,
        'ExactlyOnce'       => $ATP_TREL_30SEC
    );
    return $sem if not ref($sem);

    if (defined $success) { # Could possibly have already failed...
        my $rcode;
        if ($success == 1) {
            $rcode = unpack('l>', $rdata->[0]->[0]);
        } else {
            $rcode = $kASPNoServers;
        }
        return $rcode;
    }

    # Try getting an SPWriteContinue transaction request from the server
    my $RqCB = $self->{'atpsess'}->GetTransaction(1, sub {
        my ($txtype, $sessid, $pseq) = unpack('CCn', $_[0]{'userbytes'});
        my ($portno, $paddr) = unpack_sockaddr_at($_[0]{'sockaddr'});

        return($txtype == $OP_SP_WRITECONTINUE &&
                $sessid == $self->{'sessionid'} && $seqno == $pseq &&
                $portno == $self->{'sessport'});
    } );
    my $bufsz = unpack('n', $RqCB->{'data'});

    my $resp = &share([]);

    my $sendsz = 0;
    my $t_send = 0;
    foreach my $i (0 .. 7) { # {{{2
        last if $t_send >= $d_len;
        $sendsz = $ATP_MAXLEN;
        if ($bufsz - $t_send < $ATP_MAXLEN) {
            $sendsz = $bufsz - $t_send;
        }
        if ($d_len - $t_send < $sendsz) {
            $sendsz = $d_len - $t_send;
        }
        my $elem = &share({});
        %{$elem} = ( 'userbytes'    => pack('x[4]'),
                     'data'         => substr(${$data_r}, $t_send, $sendsz) );
        push(@{$resp}, $elem);
        $t_send += $sendsz;
    } # }}}2

    $self->{'atpsess'}->RespondTransaction($RqCB, $resp);

    $sem->down();
    # string the response bodies back together
    ${$resp_r}  = join(q{}, map { $_->[1]; } @{$rdata});
    # user bytes from the first response packet are the only ones that
    # are relevant...
    my ($errno) = unpack('l>', $rdata->[0][0]);

    return $errno;
} # }}}1

# This call only needs to be used internally; there should be no reason
# for an ASP client to call this directly.
sub SPTickle { # {{{1
    my ($self, $interval, $ntries) = @_;

    my $msg = pack('CCx[2]', $OP_SP_TICKLE, $self->{'sessionid'});
    my $sa = pack_sockaddr_at($self->{'svcport'} , atalk_aton($self->{'host'}));
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $msg,
        'ResponseLength'    => 1,
        'Timeout'           => $interval,
        'NumTries'          => $ntries,
        'PeerAddr'          => $sa,
    );
    return;
} # }}}1

1;
# vim: ts=4 ai et fdm=marker

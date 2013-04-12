package Net::Atalk::PAP;

use strict;
use warnings;
use diagnostics;

use Net::Atalk::ATP qw(:DEFAULT :xo);
use Net::Atalk;
use threads::shared;
use Readonly;

Readonly my $PAP_OpenConn           => 1;
Readonly my $PAP_OpenConnReply      => 2;
Readonly my $PAP_SendData           => 3;
Readonly my $PAP_Data               => 4;
Readonly my $PAP_Tickle             => 5;
Readonly my $PAP_CloseConn          => 6;
Readonly my $PAP_CloseConnReply     => 7;
Readonly my $PAP_SendStatus         => 8;
Readonly my $PAP_Status             => 9;

Readonly our $PAP_NoError           => 0;
Readonly our $PAP_PrinterBusy       => 0xFFFF;

Readonly our $PAP_MAXQUANTUM        => 8;
Readonly our $PAP_MAXDATA           => 512;

sub new {
    my ($class, $host, $port, %options) = @_;

    my $obj = bless {}, $class;
    $obj->{'atpsess'} = new Net::Atalk::ATP();
    return undef unless defined $obj->{'atpsess'};
    $obj->{'host'} = $host;
    $obj->{'svcport'} = $port;
    $obj->{'connid'} = 0;
    $obj->{'fquantum'} = 255;

    return $obj;
}

sub close {
    my ($self) = @_;
    $self->{'atpsess'}->close();
}

sub PAPStatus {
    my ($self, $resp_r) = @_;

    die('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    my ($rdata, $success);
    my $msg = pack('xCx[2]', $PAP_SendStatus);
    my $sa = pack_sockaddr_at($self->{'svcport'} , atalk_aton($self->{'host'}));
    my $sem = $self->{'atpsess'}->SendTransaction(
        'UserBytes'         => $msg,
        'ResponseLength'    => 1,
        'ResponseStore'     => \$rdata,
        'StatusStore'       => \$success,
        'Timeout'           => 2,
        'NumTries'          => 5,
        'PeerAddr'          => $sa,
        'ExactlyOnce'       => $ATP_TREL_30SEC,
    );
    $sem->down();
    return undef unless $success;
    my ($opid) = unpack('xCx[2]', $rdata->[0][0]);
    return undef unless $opid == $PAP_Status;
    my ($message) = unpack('x[4]a*', $rdata->[0][1]);
    $$resp_r = $message;
    return 1;
}

sub PAPOpen {
    my ($self, $waittime, $resp_r) = @_;

    die('$resp_r must be a scalar ref')
            unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

    die('Response socket already exists - PAP session already open')
            if exists $self->{'rsock'};

    my $ub = pack('CCx[2]', ++$self->{'connid'}, $PAP_OpenConn);
    my $rsock = new Net::Atalk::ATP(
            'PeerAddr'  => $self->{'host'},
            'PeerPort'  => $self->{'svcport'} );
    my $data = pack('CCn', $rsock->sockport(), $self->{'fquantum'}, $waittime);
    my $sa = pack_sockaddr_at($self->{'svcport'} , atalk_aton($self->{'host'}));

    my($rdata, $success);
    my $sem = $self->{'atpsess'}->SendTransaction(
            'UserBytes'         => $ub,
            'ResponseLength'    => 1,
            'ResponseStore'     => \$rdata,
            'StatusStore'       => \$success,
            'Timeout'           => 2,
            'NumTries'          => 5,
            'PeerAddr'          => $sa,
            'ExactlyOnce'       => $ATP_TREL_30SEC,
    );
    $sem->down();
    unless ($success) {
        $rsock->close();
        return undef;
    }
    my ($rcode, $errstr) = unpack('xxnC/a', $rdata->[0][1]);
    $$resp_r = $errstr;
    if ($rcode != $PAP_NoError) {
        $rsock->close();
        return $rcode;
    }
    $self->{'rsock'} = $rsock;
    return $rcode;
}


sub PAPSendData {
    my ($self, $data) = @_;

    my $len = length($data);
    my $pos = 0;
    my $chunksize = 512;
    my($resp, $elem);

    die('Response socket does not exist - PAP session not open')
            unless exists $self->{'rsock'};

    while ($pos < $len) {
        my $RqCB = $self->{'rsock'}->GetTransaction(1, sub {
                my ($connid, $fnid, $seqno) = unpack('CCn', $_[0]{'userbytes'});
                return ($connid == $self->{'connid'} && $fnid == $PAP_SendData);
            });

        my ($seqno) = unpack('xxn', $RqCB->{'userbytes'});

        $resp = &share([]);
        $elem = &share({});
        %$elem = ( 'userbytes'  => pack('CCCx', $self->{'connid'}, $PAP_Data,
                                        $len - $pos <= $chunksize),
                   'data'       => substr($data, $pos, $chunksize) );

        $self->{'rsock'}->RespondTransaction($RqCB, $resp);
        $pos += $chunksize;
    }
}

sub PAPClose {
    my ($self) = @_;

    die('Response socket does not exist - PAP session not open')
            unless exists $self->{'rsock'};

    my $ub = pack('CCx[2]', $self->{'connid'}, $PAP_CloseConn);
    my($rdata, $success);
    my $sem = $self->{'rsock'}->SendTransaction(
            'UserBytes'         => $ub,
            'ResponseLength'    => 1,
            'ResponseStore'     => \$rdata,
            'StatusStore'       => \$success,
            'Timeout'           => 2,
            'NumTries'          => 5,
            'ExactlyOnce'       => $ATP_TREL_30SEC,
    );
    $sem->down();
    unless ($success) {
        return undef;
    }
    return 0;

}
1;
# vim: ts=4 ai fdm=marker

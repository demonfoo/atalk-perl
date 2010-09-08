package Net::Atalk::PAP;

use strict;
use warnings;
use diagnostics;

use Net::Atalk::ATP;
use Net::Atalk;

use constant PAP_OpenConn			=> 1;
use constant PAP_OpenConnReply		=> 2;
use constant PAP_SendData			=> 3;
use constant PAP_Data				=> 4;
use constant PAP_Tickle				=> 5;
use constant PAP_CloseConn			=> 6;
use constant PAP_CloseConnReply		=> 7;
use constant PAP_SendStatus			=> 8;
use constant PAP_Status				=> 9;

use constant PAP_NoError			=> 0;
use constant PAP_PrinterBusy		=> 0xFFFF;

use constant PAP_MAXQUANTUM			=> 8;
use constant PAP_MAXDATA			=> 512;

sub new {
	my ($class, $host, $port, %options) = @_;

	my $obj = bless {}, $class;
	$$obj{'atpsess'} = new Net::Atalk::ATP();
	return undef unless defined $$obj{'atpsess'};
	$$obj{'host'} = $host;
	$$obj{'svcport'} = $port;
	$$obj{'connid'} = 0;
	$$obj{'fquantum'} = 255;

	return $obj;
}

sub PAPStatus {
	my ($self, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	my ($rdata, $success);
	my $msg = pack('xCx[2]', PAP_SendStatus);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));
	my $sem = $$self{'atpsess'}->SendTransaction(
		'UserBytes'			=> $msg,
		'ResponseLength'	=> 1,
		'ResponseStore'		=> \$rdata,
		'StatusStore'		=> \$success,
		'Timeout'			=> 2,
		'NumTries'			=> 5,
		'PeerAddr'			=> $sa,
		'ExactlyOnce'		=> ATP_TREL_30SEC,
	);
	$sem->down();
	return undef unless $success;
	my ($opid) = unpack('xCx[2]', $$rdata[0][0]);
	return undef unless $opid == PAP_Status;
	my ($message) = unpack('x[4]a*', $$rdata[0][1]);
	$$resp_r = $message;
	return 1;
}

sub PAPOpen {
	my ($self, $waittime, $resp_r) = @_;

	die('$resp_r must be a scalar ref')
			unless ref($resp_r) eq 'SCALAR' or ref($resp_r) eq 'REF';

	die('Response socket already exists - PAP session already open')
			if exists $$self{'rsock'};

	my $ub = pack('CCx[2]', ++$$self{'connid'}, PAP_OpenConn);
	my $rsock = new Net::Atalk::ATP(
			'PeerAddr'	=> $$self{'host'},
			'PeerPort'	=> $$self{'svcport'} );
	my $data = pack('CCn', $rsock->sockport(), $$self{'fquantum'}, $waittime);
	my $sa = pack_sockaddr_at($$self{'svcport'} , atalk_aton($$self{'host'}));

	my($rdata, $success);
	my $sem = $$obj{'atpsess'}->SendTransaction(
			'UserBytes'			=> $ub,
			'ResponseLength'	=> 1,
			'ResponseStore'		=> \$rdata,
			'StatusStore'		=> \$success,
			'Timeout'			=> 2,
			'NumTries'			=> 5,
			'PeerAddr'			=> $sa,
			'ExactlyOnce'		=> ATP_TREL_30SEC,
	);
	$sem->down();
	unless ($success) {
		$rsock->close();
		return undef;
	}
	my ($rcode, $errstr) = unpack('xxn', $$rdata[0][1]);
	$$resp_r = $errstr;
	if ($rcode != PAP_NoError) {
		$rsock->close();
		return $rcode;
	}
	$$self{'rsock'} = $rsock;
	return $rcode;
}


sub SendData {
	my ($self, $data) = @_;

	my $RqCB = $$self{'rsock'}->GetTransaction(1, sub {
			my ($connid, $fnid, $seqno) = unpack('CCn', $_[0]{'userbytes'});
			return ($connid == $$self{'connid'} && fnid == PAP_SendData);
		});
}
1;
# vim: ts=4 ai fdm=marker

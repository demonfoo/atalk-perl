# IO::Socket::DDP.pm

package IO::Socket::DDP;

use strict;
use warnings;
use IO::Socket;
use Net::Atalk;
use Net::Atalk::NBP;
use Carp;
use Errno qw(EINVAL ETIMEDOUT);
use English qw(-no_match_vars);

use base qw(IO::Socket);
our $VERSION = '0.50';

IO::Socket::DDP->register_domain( AF_APPLETALK );

my %socket_type = ( ddp => SOCK_DGRAM );
my %proto_number;
$proto_number{ddp}  = 37;
my %proto_name      = reverse %proto_number;

sub new {
    my $class = shift;
    unshift @_, 'PeerAddr' if scalar @_ == 1;
    return $class->SUPER::new(@_);
}

sub _cache_proto {
    my @proto = @_;
    for (map { lc $_ } $proto[0], split q{ }, $proto[1]) {
        $proto_number{$_} = $proto[2];
    }
    $proto_name{$proto[2]} = $proto[0];
    return;
}

sub _get_proto_number {
    my $name = lc shift;
    return unless defined $name;
    return $proto_number{$name} if exists $proto_number{$name};

    my @proto = getprotobyname $name;
    return unless @proto;
    _cache_proto(@proto);

    return $proto[2];
}

sub _get_proto_name {
    my $num = shift;
    return unless defined $num;
    return $proto_name{$num} if exists $proto_name{$num};

    my @proto = getprotobynumber $num;
    return unless @proto;
    _cache_proto(@proto);

    return $proto[0];
}

sub _sock_info {
    my($addr,$port,$proto) = @_;
    my $origport = $port;
    my @serv = ();

    $port = $1 if(defined $addr && $addr =~ s{:([\w()/]+)$}{}s);

    if(defined $proto  && $proto =~ /\D/s) {
        my $num = _get_proto_number($proto);
        if (not defined $num) {
            $EVAL_ERROR = "Bad protocol '$proto'";
            return;
        }
        $proto = $num;
    }

    if(defined $port) {
        my $defport = ($port =~ s{[(](\d+)[)]$}{}s) ? $1 : undef;
        my $pnum = ($port =~ m{^(\d+)$}s)[0];

        @serv = getservbyname($port, _get_proto_name($proto) || q{})
            if ($port =~ m{\D});

        $port = $serv[2] || $defport || $pnum;
        if (not defined $port) {
            $EVAL_ERROR = "Bad service '$origport'";
            return;
        }

        $proto = _get_proto_number($serv[3]) if @serv && !$proto;
    }

    return ($addr || undef,
            $port || undef,
            $proto || undef,
           );
}

sub _error {
    my $sock = shift;
    my $err = shift;
    {
        local $ERRNO = 0;
        my $title = ref($sock) . q{: };
        $EVAL_ERROR = join q{}, $_[0] =~ /^$title/s ? q{} : $title, @_;
        $sock->close() if defined fileno $sock;
    }
    $ERRNO = $err;
    return;
}

sub _get_addr {
    my($sock, $addr_str, $port_str, $multi) = @_;
    my @addr;
    my $h = atalk_aton($addr_str);
    if (defined $h) {
        @addr = ($h);
    }
    else {
        @addr = map { $_->[0] } NBPLookup($addr_str, $port_str, undef, undef);
        if (!$multi) {
            @addr = ($addr[0]);
        }
    }
    return @addr;
}

sub configure {
    my($sock,$arg) = @_;
    my($lport,$rport,$laddr,$raddr,$proto,$type);

    $arg->{LocalAddr} = $arg->{LocalHost}
        if exists $arg->{LocalHost} && !exists $arg->{LocalAddr};

    ($laddr,$lport,$proto) = _sock_info($arg->{LocalAddr},
                                        $arg->{LocalPort},
                                        $arg->{Proto})
                        or return _error($sock, $ERRNO, $EVAL_ERROR);

    $laddr = defined $laddr ? atalk_aton($laddr)
                            : $ATADDR_ANY;

    return _error($sock, EINVAL, q{Bad hostname '},$arg->{LocalAddr},q{'})
        unless(defined $laddr);

    $arg->{PeerAddr} = $arg->{PeerHost}
        if exists $arg->{PeerHost} && !exists $arg->{PeerAddr};

    if (not exists $arg->{Listen}) {
        ($raddr,$rport,$proto) = _sock_info($arg->{PeerAddr},
                                            $arg->{PeerPort},
                                            $proto)
                        or return _error($sock, $ERRNO, $EVAL_ERROR);
    }

    $proto ||= _get_proto_number('ddp');

    $type = $arg->{Type} || $socket_type{lc _get_proto_name($proto)};

    my @raddr = ();

    if(defined $raddr) {
        @raddr = $sock->_get_addr($raddr, $rport, $arg->{MultiHomed});
        return _error($sock, EINVAL, q{Bad hostname '},$arg->{PeerAddr},q{'})
            unless @raddr;
    }

    while(1) {

        $sock->socket(AF_APPLETALK, $type, 0) or
            return _error($sock, $ERRNO, "$ERRNO");

        if (defined $arg->{Blocking}) {
            defined $sock->blocking($arg->{Blocking})
                or return _error($sock, $ERRNO, "$ERRNO");
        }

        if ($arg->{Reuse} || $arg->{ReuseAddr}) {
            $sock->sockopt(SO_REUSEADDR,1) or
                    return _error($sock, $ERRNO, "$ERRNO");
        }

        if ($arg->{ReusePort}) {
            $sock->sockopt(SO_REUSEPORT,1) or
                    return _error($sock, $ERRNO, "$ERRNO");
        }

	if ($arg->{Broadcast}) {
		$sock->sockopt(SO_BROADCAST,1) or
		    return _error($sock, $ERRNO, "$ERRNO");
	}

	if($lport || exists $arg->{Listen} || $OSNAME ne 'linux') {
	    $sock->bind($lport || 0, $laddr) or
		    return _error($sock, $ERRNO, "$ERRNO");
	}

	if(exists $arg->{Listen}) {
	    $sock->listen($arg->{Listen} || 5) or
		return _error($sock, $ERRNO, "$ERRNO");
	    last;
	}

 	# don't try to connect unless we're given a PeerAddr
 	last unless exists($arg->{PeerAddr});

        $raddr = shift @raddr;

	return _error($sock, EINVAL, 'Cannot determine remote port')
		unless($rport || $type == SOCK_DGRAM || $type == SOCK_RAW);

	last
	    unless($type == SOCK_STREAM || defined $raddr);

	return _error($sock, EINVAL, q{Bad hostname '},$arg->{PeerAddr},q{'})
	    unless defined $raddr;

#        my $timeout = ${*$sock}{io_socket_timeout};
#        my $before = time() if $timeout;

	undef $EVAL_ERROR;
    if ($sock->connect(pack_sockaddr_at($rport, $raddr))) {
#            ${*$sock}{io_socket_timeout} = $timeout;
        return $sock;
    }

	return _error($sock, $ERRNO, $EVAL_ERROR || 'Timeout')
	    unless @raddr;

#	if ($timeout) {
#	    my $new_timeout = $timeout - (time() - $before);
#	    return _error($sock, ETIMEDOUT, 'Timeout') if $new_timeout <= 0;
#	    ${*$sock}{io_socket_timeout} = $new_timeout;
#        }

    }

    return $sock;
}

sub connect {
    scalar(@_) == 2 or scalar(@_) == 3 or
       croak 'usage: $sock->connect(NAME) or $sock->connect(PORT, ADDR)';
    my $sock = shift;
    return $sock->SUPER::connect(scalar(@_) == 1 ? shift : pack_sockaddr_at(@_));
}

sub bind {
    scalar(@_) == 2 or scalar(@_) == 3 or
       croak 'usage: $sock->bind(NAME) or $sock->bind(PORT, ADDR)';
    my $sock = shift;
    return $sock->SUPER::bind(scalar(@_) == 1 ? shift : pack_sockaddr_at(@_))
}

sub sockaddr {
    scalar(@_) == 1 or croak 'usage: $sock->sockaddr()';
    my($sock) = @_;
    my $name = $sock->sockname;
    return($name ? (unpack_sockaddr_at($name))[1] : undef);
}

sub sockport {
    scalar(@_) == 1 or croak 'usage: $sock->sockport()';
    my($sock) = @_;
    my $name = $sock->sockname;
    return($name ? (unpack_sockaddr_at($name))[0] : undef);
}

sub sockhost {
    scalar(@_) == 1 or croak 'usage: $sock->sockhost()';
    my($sock) = @_;
    my $addr = $sock->sockaddr;
    return($addr ? atalk_ntoa($addr) : undef);
}

sub peeraddr {
    scalar(@_) == 1 or croak 'usage: $sock->peeraddr()';
    my($sock) = @_;
    my $name = $sock->peername;
    return($name ? (unpack_sockaddr_at($name))[1] : undef);
}

sub peerport {
    scalar(@_) == 1 or croak 'usage: $sock->peerport()';
    my($sock) = @_;
    my $name = $sock->peername;
    return($name ? (unpack_sockaddr_at($name))[0] : undef);
}

sub peerhost {
    scalar(@_) == 1 or croak 'usage: $sock->peerhost()';
    my($sock) = @_;
    my $addr = $sock->peeraddr;
    return($addr ? atalk_ntoa($addr) : undef);
}

1;

__END__


# This is Net::Atalk::ATP. It implements (mostly correctly) the ATP
# (AppleTalk Transaction Protocol) layer of the AppleTalk protocol
# family, which adds a transactional request/response layer over the
# DDP datagram protocol.
package Net::Atalk::ATP;

use strict;
use warnings;

use constant kASPNoError        => 0;
use constant kASPBadVersNum     => -1066;
use constant kASPBufTooSmall    => -1067;
use constant kASPNoMoreSessions => -1068;
use constant kASPNoServers      => -1069;
use constant kASPParamErr       => -1070;
use constant kASPServerBusy     => -1071;
use constant kASPSessClosed     => -1072;
use constant kASPSizeErr        => -1073;
use constant kASPTooManyClients => -1074;
use constant kASPNoAck          => -1075;

# Disabling strict refs because for the installable transaction filters
# to work, I have to be able to have some way to deref the subroutines,
# and we can't pass SUB refs from thread to thread.
no strict qw(refs);

use IO::Socket::DDP;
use Net::Atalk;
use Time::HiRes qw(gettimeofday);
use IO::Poll qw(POLLIN);
use IO::Handle;
use threads;
use threads::shared;
use Thread::Semaphore;
use Exporter qw(import);
use Scalar::Util qw(dualvar);

# ATP message types.
use constant ATP_TReq           => (0x1 << 6);  # Transaction request
use constant ATP_TResp          => (0x2 << 6);  # Transaction response
use constant ATP_TRel           => (0x3 << 6);  # Transaction release

# Fields of the control byte (first byte) in an ATP message.
use constant ATP_CTL_FNCODE     => 0xC0;
use constant ATP_CTL_XOBIT      => 0x20;    # transaction must happen
                                            # exactly once
use constant ATP_CTL_EOMBIT     => 0x10;    # packet is end of message
use constant ATP_CTL_STSBIT     => 0x08;    # send transaction status; upon
                                            # receipt by originator, resend
                                            # TReq packet
use constant ATP_CTL_TREL_TMOUT => 0x07;

# TRel timeout periods for XO (exactly-once) transactions. Ignored by
# AppleTalk Phase1 implementations; I don't think this applies to anything
# except really, really old stuff.
use constant ATP_TREL_30SEC     => 0x00;
use constant ATP_TREL_1MIN      => 0x01;
use constant ATP_TREL_2MIN      => 0x02;
use constant ATP_TREL_4MIN      => 0x03;
use constant ATP_TREL_8MIN      => 0x04;

# The maximum length of the ATP message body.
use constant ATP_MAXLEN         => 578;

# symbols to export
our @EXPORT = qw(ATP_TREL_30SEC ATP_TREL_1MIN ATP_TREL_2MIN ATP_TREL_4MIN
        ATP_TREL_8MIN ATP_MAXLEN kASPNoError kASPBadVersNum kASPBufTooSmall
        kASPNoMoreSessions kASPNoServers kASPParamErr kASPServerBusy
        kASPSessClosed kASPSizeErr kASPTooManyClients kASPNoAck);

my $atp_header :shared;
$atp_header = 'CCCna[4]a*';
my @atp_header_fields :shared;
@atp_header_fields = ('ddp_type', 'ctl', 'bmp_seq', 'txid', 'userbytes',
        'data');
my %xo_timeouts :shared;
%xo_timeouts = (
                 &ATP_TREL_30SEC    => 30,
                 &ATP_TREL_1MIN     => 60,
                 &ATP_TREL_2MIN     => 120,
                 &ATP_TREL_4MIN     => 240,
                 &ATP_TREL_8MIN     => 480,
               );

sub new { # {{{1
    my ($class, %sockopts) = @_;

    my $obj = bless {}, $class;

    my $shared = &share({});
    %$shared = (
                 'running'      => 0,
                 'exit'         => 0,
                 'last_txid'    => int(rand(2 ** 16)),
                 'conn_fd'      => undef,
                 'conn_sem'     => new Thread::Semaphore(0),
                 'TxCB_list'    => &share({}),
                 'RqCB_list'    => &share({}),
                 'RqCB_txq'     => &share([]),
                 'RqCB_sem'     => new Thread::Semaphore(0),
                 'RqFilters'    => &share([]),
                 'TimedCBs'     => &share([]),
                 'RspCB_list'   => &share({}),
               );
    $obj->{'Shared'}        = $shared;
    my $thread = threads->create(\&thread_core, $shared, %sockopts);
    $obj->{'Dispatcher'}    = $thread;
    $shared->{'conn_sem'}->down();
    $obj->{'Conn'} = new IO::Handle;
    if ($shared->{'running'} == 1) {
        $obj->{'Conn'}->fdopen($shared->{'conn_fd'}, 'w');
    }
    else {
        $obj->{'Dispatcher'}->join();
    }
    $shared->{'conn_sem'}->up();

    if (exists $shared->{'errno'}) {
        $! = dualvar $shared->{'errno'}, $shared->{'error'};
    }
    return($shared->{'running'} == 1 ? $obj : undef);
} # }}}1

sub close { # {{{1
    my ($self) = @_;
    $self->{'Shared'}{'exit'} = 1;
    $self->{'Dispatcher'}->join();
} # }}}1

sub sockaddr { # {{{1
    my ($self) = @_;
    return $self->{'Shared'}{'sockaddr'};
} # }}}1

sub sockport { # {{{1
    my ($self) = @_;
    return $self->{'Shared'}{'sockport'};
} # }}}1

sub sockdomain { # {{{1
    my ($self) = @_;
    return $self->{'Shared'}{'sockdomain'};
} # }}}1

# This function is the body of the thread. Similar to DSI, this is a
# hybrid-dispatcher arrangement - responses are sent directly from the
# main thread, but messages coming from the peer are handled in the
# thread and processed and dispatched from there.
sub thread_core { # {{{1
    my ($shared, %sockopts) = @_;

    # Set up the datagram socket to the target host. There's no connection
    # status per-se, since DDP is datagram-oriented, not connection-oriented
    # like TCP is.
    my %connect_args = ( 'Proto'        => 'ddp',
                         'Type'         => SOCK_DGRAM,
                         %sockopts );
    my $conn = new IO::Socket::DDP(%connect_args);
    unless ($conn && $conn->sockaddr()) {
        $shared->{'running'}    = -1;
        $shared->{'error'}      = $!;
        $shared->{'errno'}      = int($!);
        $shared->{'conn_sem'}->up();
        return;
    }
    $shared->{'running'}    = 1;

    $shared->{'conn_fd'}    = fileno($conn);
    $shared->{'sockaddr'}   = $conn->sockaddr();
    $shared->{'sockport'}   = $conn->sockport();
    #$shared->{'peeraddr'}   = $conn->peeraddr();
    #$shared->{'peerport'}   = $conn->peerport();
    $shared->{'sockdomain'} = AF_APPLETALK;
    $shared->{'conn_sem'}->up();

    # Set up a poll object for checking out our socket. Also preallocate
    # several variables which will be used in the main loop.
    my $poll = new IO::Poll();
    $poll->mask($conn, POLLIN);
    my ($txid, $TxCB, $time, $from, $msg, %msgdata, $msgtype,
        $wants_sts, $is_eom, $seqno, $RqCB, $is_xo, $xo_tmout, $RspCB, $seq,
        $pktdata, $ctl_byte, $filter, $rv, $item, $stamp, $port, $paddr,
        $addr, $txkey, $rec, $cb);

MAINLOOP:
    while ($shared->{'exit'} == 0) { # {{{2
        $time = gettimeofday();

        # Check for any timed callbacks.
        foreach $rec (@{$shared->{'TimedCBs'}}) { # {{{3
            if (($rec->{'last_called'} + $rec->{'period'}) < $time) {
                $cb = $rec->{'callback'};
                &{$cb->[0]}(@$cb[1 .. $#$cb], $time, $shared);
                $rec->{'last_called'} = $time;
            }
        } # }}}3

        # Okay, now we need to check existing outbound transactions for
        # status, resends, cleanups, etc...
        foreach $txid (keys %{$shared->{'TxCB_list'}}) { # {{{3
            $TxCB = $shared->{'TxCB_list'}{$txid};
            next if (($time - $TxCB->{'stamp'}) < $TxCB->{'tmout'});

            # We're past the indicated timeout duration for the
            # transaction, so now we have to decide its fate.
            if (!$TxCB->{'ntries'}) {
                # Okay, you've had enough go-arounds. Time to put
                # this dog down.
                ${$TxCB->{'sflag'}} = 0;
                delete $shared->{'TxCB_list'}{$txid};
                $TxCB->{'sem'}->up();
                next;
            }

            # Packet data needs to be resent. Sequence data will be updated
            # in the structure. We need to decrement the retry counter,
            # copy the updated sequence bitmap back into the packet data,
            # resend the packet, and update the retry counter.

            # -1 is special, it means "just keep trying forever"
            if ($TxCB->{'ntries'} != -1) { $TxCB->{'ntries'}-- }

            # Update packet data with new sequence bitmap.
            substr($TxCB->{'msg'}, 2, 1, pack('C', $TxCB->{'seq_bmp'}));

            $shared->{'conn_sem'}->down();
            send($conn, $TxCB->{'msg'}, 0, $TxCB->{'target'});
            $TxCB->{'stamp'} = $time;
            $shared->{'conn_sem'}->up();
        } # }}}3

        # Check the XO transaction completion list as well.
        foreach $txkey (keys %{$shared->{'RspCB_list'}}) { # {{{3
            # If the transaction is past its keep-by, just delete it, nothing
            # more to be done on our end.
            $RspCB = $shared->{'RspCB_list'}{$txkey};
            delete $shared->{'RspCB_list'}{$txkey}
                    if (($time - $RspCB->{'stamp'}) >= $RspCB->{'tmout'});
        } # }}}3

        # Check the socket for incoming packets. If there's nothing, just
        # loop again.
        next MAINLOOP unless $poll->poll(0.5);

        # We've got something. Read in a potential packet. We know it's
        # never going to be larger than DDP_MAXSZ.
        $shared->{'conn_sem'}->down();
        $from = recv($conn, $msg, DDP_MAXSZ, 0);
        $shared->{'conn_sem'}->up();
        next MAINLOOP unless defined $from;

        # Unpack the packet into its constituent fields, and quietly
        # move on if its DDP type field is wrong.
        @msgdata{@atp_header_fields} = unpack($atp_header, $msg);
        next MAINLOOP unless $msgdata{'ddp_type'} == DDPTYPE_ATP;

        # Let's see what kind of message we've been sent.
        $msgtype = $msgdata{'ctl'} & ATP_CTL_FNCODE;
        $txid = $msgdata{'txid'};

        # Get the requester source address and port and jam everything
        # together to make a transaction key, so separate requesters
        # can't stomp on one another's transaction requests.
        ($port, $paddr) = unpack_sockaddr_at($from);
        $addr = atalk_ntoa($paddr);
        $txkey = join('/', $addr, $port, $txid);

        if ($msgtype == ATP_TReq) { # {{{3
            # Remote is asking to initiate a transaction with us.
            $is_xo      = $msgdata{'ctl'} & ATP_CTL_XOBIT;
            $xo_tmout   = $msgdata{'ctl'} & ATP_CTL_TREL_TMOUT;

            # Ignore a duplicate transaction request.
            next MAINLOOP if exists $shared->{'RqCB_list'}{$txkey};

            # If there's an XO completion handler in place, then resend
            # whatever packets the peer indicates it wants.
            if (exists $shared->{'RspCB_list'}{$txkey}) { # {{{4
                $RspCB      = $shared->{'RspCB_list'}{$txkey};
                $RqCB       = $RspCB->{'RqCB'};
                $pktdata    = $RspCB->{'RespData'};

                foreach my $seq (0 .. $#$pktdata) {
                    # Check if the sequence mask bit corresponding to
                    # the sequence number is set.
                    next unless $RqCB->{'seq_bmp'} & (1 << $seq);

                    $shared->{'conn_sem'}->down();
                    send($conn, $pktdata->[$seq], 0, $RqCB->{'sockaddr'});
                    $shared->{'conn_sem'}->up();
                }
                $RspCB->{'stamp'} = gettimeofday();
                next MAINLOOP;
            } # }}}4
            $RqCB = &share({});
            # Set up the transaction request block.
            %$RqCB = (
                      'txid'            => $txid,
                      'is_xo'           => $is_xo,
                      'xo_tmout_bits'   => $xo_tmout,
                      'xo_tmout'        => $xo_timeouts{$xo_tmout},
                      'seq_bmp'         => $msgdata{'bmp_seq'},
                      'userbytes'       => $msgdata{'userbytes'},
                      'data'            => $msgdata{'data'},
                      'sockaddr'        => $from,
                    );

            # Try running the request block through any registered
            # transaction filter handlers before putting it on the
            # list for outside processing.
            foreach $filter (@{$shared->{'RqFilters'}}) { # {{{4
                $rv = &{$filter->[0]}(@$filter[1 .. $#$filter], $RqCB);
                # If the filter returned something other than undef,
                # it is (well, should be) an array ref containing
                # ATP user byte and payload blocks.
                next if not $rv;
                $pktdata = &share([]);
                foreach my $seq (0 .. $#$rv) {
                    $item = $rv->[$seq];
                    $ctl_byte = ATP_TResp;
                    # last packet in provided set, so tell the
                    # requester that this is end of message...
                    if ($seq == $#$rv) { $ctl_byte |= ATP_CTL_EOMBIT }
                    $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte,
                            $seq, $txid, @$item{'userbytes', 'data'});
                    $pktdata->[$seq] = $msg;

                    next unless $RqCB->{'seq_bmp'} & (1 << $seq);

                    # Okay, let's try registering the RspCB just
                    # before the last packet posts to the server...
                    if ($RqCB->{'is_xo'} && $seq == $#$rv) {
                        $RspCB = &share({});
                        %$RspCB = (
                            'RqCB'      => $RqCB,
                            'RespData'  => $pktdata,
                            'tmout'     => $RqCB->{'xo_tmout'},
                        );
                        $RspCB->{'stamp'}               = gettimeofday();
                        $shared->{'RspCB_list'}{$txkey} = $RspCB;
                    }

                    $shared->{'conn_sem'}->down();
                    send($conn, $msg, 0, $RqCB->{'sockaddr'});
                    $shared->{'conn_sem'}->up();
                }
                next MAINLOOP;
            } # }}}4

            $shared->{'RqCB_list'}{$txkey} = $RqCB;
            push(@{$shared->{'RqCB_txq'}}, $RqCB);
            $shared->{'RqCB_sem'}->up();
        } # }}}3
        elsif ($msgtype == ATP_TResp) { # {{{3
            # Remote is responding to a transaction we initiated.

            # Ignore a transaction response to a transaction that we don't
            # know, either because we didn't initiate it, or because we
            # tried it enough times and gave up.
            next MAINLOOP unless exists $shared->{'TxCB_list'}{$txid};

            # Get the transaction block, and grab a few bits of info
            # out of it to keep them at hand.
            $TxCB       = $shared->{'TxCB_list'}{$txid};
            $is_eom     = $msgdata{'ctl'} & ATP_CTL_EOMBIT;
            $wants_sts  = $msgdata{'ctl'} & ATP_CTL_STSBIT;
            $seqno      = $msgdata{'bmp_seq'};

            # If the server says this packet is the end of the transaction
            # set, mask off any higher bits in the sequence bitmap.
            if ($is_eom) { $TxCB->{'seq_bmp'} &= 0xFF >> (7 - $seqno) }

            # If the sequence bit for this packet is already cleared,
            # just quietly move on.
            next MAINLOOP unless $TxCB->{'seq_bmp'} & (1 << $seqno);

            # Put data into the array of stored payloads.
            $TxCB->{'response'}[$seqno] = &share([]);
            @{$TxCB->{'response'}[$seqno]} = 
                    @msgdata{'userbytes', 'data'};
            # Clear the corresponding bit in the sequence bitmap.
            $TxCB->{'seq_bmp'} &= ~(1 << $seqno) & 0xFF;

            # If the sequence bitmap is now 0, then we've received
            # all the data we're going to.
            if (!$TxCB->{'seq_bmp'}) { # {{{4
                ${$TxCB->{'sflag'}} = 1;
                delete $shared->{'TxCB_list'}{$txid};
                $TxCB->{'sem'}->up();

                # If it was an XO transaction, we should send a TRel here.
                next MAINLOOP if !$TxCB->{'is_xo'};

                # Don't need to preserve the XO bits.
                substr($TxCB->{'msg'}, 1, 1, pack('C', ATP_TRel));
                $shared->{'conn_sem'}->down();
                send($conn, $TxCB->{'msg'}, 0, $TxCB->{'target'});
                $shared->{'conn_sem'}->up();
                next MAINLOOP;
            } # }}}4

            # If the server wants an STS, or the sequence number is
            # high enough that it's not going up further but there are
            # still packets we need, then resend the request packet.
            next MAINLOOP unless $wants_sts or ($TxCB->{'seq_bmp'} and
                    !($TxCB->{'seq_bmp'} >> $seqno));

            # Update packet data with new sequence bitmap.
            substr($TxCB->{'msg'}, 2, 1, pack('C', $TxCB->{'seq_bmp'}));

            $shared->{'conn_sem'}->down();
            send($conn, $TxCB->{'msg'}, 0, $TxCB->{'target'});
            $TxCB->{'stamp'} = gettimeofday();
            $shared->{'conn_sem'}->up();
        } # }}}3
        elsif ($msgtype == ATP_TRel) { # {{{3
            # Peer has sent us a transaction release message, so drop
            # the pending RspCB if one is present. I think we can
            # safely delete even if it's not there; saves us the time
            # of checking.
            delete $shared->{'RspCB_list'}{$txkey};
        } # }}}3
    } # }}}2
    $shared->{'running'} = -1;
    # If we reach this point, we're exiting the thread. Notify any pending
    # waiting calls that they've failed before we go away.
    foreach $TxCB (values %{$shared->{'TxCB_list'}}) {
        ${$TxCB->{'sflag'}} = 0;
        $TxCB->{'sem'}->up();
    }
    # If someone's blocking in GetTransaction(), this will snap them out
    # of it...
    $shared->{'RqCB_sem'}->up();

    undef $shared->{'conn_fd'};
    CORE::close($conn);
} # }}}1

sub SendTransaction { # {{{1
    my ($self, %options) = @_;

    die('UserBytes must be provided')
            unless exists $options{'UserBytes'};
    $options{'Data'} ||= '';
    die('ResponseLength must be provided')
            unless exists $options{'ResponseLength'};
    $options{'ResponseStore'} ||= *foo{SCALAR};
    die('ResponseStore must be provided and be a scalar ref')
            unless ref($options{'ResponseStore'}) eq 'SCALAR' or
                 ref($options{'ResponseStore'}) eq 'REF';
    $options{'StatusStore'} ||= *bar{SCALAR};
    die('StatusStore must be provided and be a scalar ref')
            unless ref($options{'StatusStore'}) eq 'SCALAR' or
                 ref($options{'StatusStore'}) eq 'REF';
    die('Timeout must be provided') unless exists $options{'Timeout'};
    $options{'NumTries'} ||= -1;
    $options{'PeerAddr'} ||= undef;

    # Check a few parameters before we proceed.
    return kASPSizeErr if length($options{'Data'}) > ATP_MAXLEN;
    return if $options{'ResponseLength'} > 8;
    return if length($options{'UserBytes'}) > 4;
    return kASPSessClosed unless $self->{'Shared'}{'running'} == 1;

    # Set up the outgoing transaction request packet.
    my $ctl_byte = ATP_TReq;
    if (exists $options{'ExactlyOnce'}) {
        $ctl_byte |= ATP_CTL_XOBIT | $options{'ExactlyOnce'};
    }
    my $seq_bmp = 0xFF >> (8 - $options{'ResponseLength'});

    my $TxCB_queue = $self->{'Shared'}{'TxCB_list'};
    my $txid;
    # Okay, have to handle potential transaction ID collisions due to
    # wrapping...
    do {
        $txid = ++$self->{'Shared'}{'last_txid'} % (2 ** 16);
    } while (exists $TxCB_queue->{$txid});

    my $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq_bmp, $txid,
            $options{'UserBytes'}, $options{'Data'});

    # Set up the transaction control block.
    my $ntries = $options{'NumTries'};
    my $TxCB = &share({});
    %$TxCB = (
                 'msg'      => $msg,
                 'ntries'   => $ntries == -1 ? $ntries : ($ntries - 1),
                 'response' => &share([]),
                 'seq_bmp'  => $seq_bmp,
                 'is_xo'    => exists $options{'ExactlyOnce'},
                 'tmout'    => $options{'Timeout'},
                 'sem'      => new Thread::Semaphore(0),
                 'sflag'    => &share($options{'StatusStore'}),
                 'target'   => $options{'PeerAddr'},
               );
    ${$options{'ResponseStore'}} = $TxCB->{'response'};

    # Indicate this as when the transaction has started (have to do this
    # before we queue the TxCB)...
    $TxCB->{'stamp'} = gettimeofday();

    # Register our transaction control block so the thread can see it,
    # since we have no idea how soon the response will come back from
    # who we're talking to.
    $TxCB_queue->{$txid} = $TxCB;

    # Send request packet.
    $self->{'Shared'}{'conn_sem'}->down();
    send($self->{'Conn'}, $msg, 0, $options{'PeerAddr'});
    $self->{'Shared'}{'conn_sem'}->up();

    return $TxCB->{'sem'};
} # }}}1

sub GetTransaction { # {{{1
    my ($self, $do_block, $filter) = @_;

    # Get the ref for the queue of incoming transactions.
    my $RqCB_queue = $self->{'Shared'}{'RqCB_txq'};

    # Handle optionally blocking for a new transaction.
    $self->{'Shared'}{'RqCB_sem'}->down() if $do_block;

    foreach my $i (0 .. $#$RqCB_queue) {
        # If no transaction filter was passed, or the transaction filter
        # returned true, grab the RqCB out of the queue, remove it from
        # the pending queue, and return it to the caller.
        if (!defined($filter) || &$filter($RqCB_queue->[$i])) {
            my $RqCB = $RqCB_queue->[$i];
            @$RqCB_queue = @$RqCB_queue[0 .. ($i - 1),
                    ($i + 1) .. $#$RqCB_queue];
            # If the caller asked to block to wait, restore the semaphore
            # count to where it should be.
            $self->{'Shared'}{'RqCB_sem'}->up($i - 1) if $do_block && $i > 0;
            return $RqCB;
        }
        # Down the sem again, so that if we're at the last, we'll block
        # until another is enqueued.
        $self->{'Shared'}{'RqCB_sem'}->down() if $do_block;
    }
    # If we reach this point, the caller didn't ask to block *and* no
    # transactions matched (or none were in the waiting queue), so just
    # send back an undef.
    return;
} # }}}1

sub RespondTransaction { # {{{1
    my ($self, $RqCB, $resp_r) = @_;
    
    die('$resp_r must be an array') unless ref($resp_r) eq 'ARRAY';

    # If the transaction response is too big/small, just abort the whole
    # mess now.
    die('Ridiculous number of response packets supplied')
            if scalar(@$resp_r) > 8 or scalar(@$resp_r) < 1;

    # Abort if the transaction ID that the caller indicated is unknown to us.
    my ($port, $paddr) = unpack_sockaddr_at($RqCB->{'sockaddr'});
    my $addr = atalk_ntoa($paddr);
    my $txkey = join('/', $addr, $port, $RqCB->{'txid'});
    die() unless exists $self->{'Shared'}{'RqCB_list'}{$txkey};

    my $pktdata = &share([]);

    foreach my $seq (0 .. $#$resp_r) {
        die('$resp_r->[' . $seq . '] was not a hash ref')
                unless ref($resp_r->[$seq]) eq 'HASH';
        my $ctl_byte = ATP_TResp;
        # last packet in provided set, so tell the requester that this is
        # end of message...
        if ($seq == $#$resp_r) { $ctl_byte |= ATP_CTL_EOMBIT }
        my $msg = pack($atp_header, DDPTYPE_ATP, $ctl_byte, $seq,
                $RqCB->{'txid'}, @{$resp_r->[$seq]}{'userbytes', 'data'});
        $pktdata->[$seq] = $msg;

        next unless $RqCB->{'seq_bmp'} & (1 << $seq);

        # Okay, let's try registering the RspCB just before the last packet
        # posts to the server...
        if ($RqCB->{'is_xo'} && $seq == $#$resp_r) {
            my $RspCB = &share({});
            %$RspCB = (
                'RqCB'      => $RqCB,
                'RespData'  => $pktdata,
                'tmout'     => $RqCB->{'xo_tmout'},
            );
            $RspCB->{'stamp'}                        = gettimeofday();
            $self->{'Shared'}{'RspCB_list'}{$txkey}  = $RspCB;
        }

        $self->{'Shared'}{'conn_sem'}->down();
        send($self->{'Conn'}, $msg, 0, $RqCB->{'sockaddr'});
        $self->{'Shared'}{'conn_sem'}->up();
    }

    # Remove the transaction from the stored list.
    delete $self->{'Shared'}{'RqCB_list'}{$txkey};
} # }}}1

# The idea here is to be able to pass a subroutine that looks at the
# transaction block and, if it's known, handle the transaction without
# passing it on to transaction queue at all.
sub AddTransactionFilter { # {{{1
    my ($self, $filter) = @_;

    push(@{$self->{'Shared'}{'RqFilters'}}, $filter);
} # }}}1

sub AddPeriodicCallback { # {{{1
    my ($self, $period, $callback) = @_;

    my $cb_rec = &share({});
    %$cb_rec = (
        'callback'      => $callback,
        'period'        => $period,
        'last_called'   => 0,
    );
    push(@{$self->{'Shared'}{'TimedCBs'}}, $cb_rec);
} # }}}1

1;
# vim: ts=4 fdm=marker

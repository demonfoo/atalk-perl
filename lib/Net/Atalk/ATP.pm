# This is Net::Atalk::ATP. It implements (mostly correctly) the ATP
# (AppleTalk Transaction Protocol) layer of the AppleTalk protocol
# family, which adds a transactional request/response layer over the
# DDP datagram protocol.
package Net::Atalk::ATP;

use strict;
use warnings;
use diagnostics;
use Readonly;

# Enables a nice call trace on warning events.
use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

use IO::Socket::DDP;
use Net::Atalk;
use Time::HiRes qw(gettimeofday usleep);
use IO::Poll qw(POLLIN);
use IO::Handle;
use threads;
use threads::shared;
use Thread::Semaphore;
use Exporter qw(import);
use Scalar::Util qw(dualvar);
use English qw(-no_match_vars);
use Errno qw(ESHUTDOWN);

# ATP message types.
Readonly my $ATP_TReq           => (0x1 << 6);  # Transaction request
Readonly my $ATP_TResp          => (0x2 << 6);  # Transaction response
Readonly my $ATP_TRel           => (0x3 << 6);  # Transaction release

# Fields of the control byte (first byte) in an ATP message.
Readonly my $ATP_CTL_FNCODE     => 0xC0;
Readonly my $ATP_CTL_XOBIT      => 0x20;    # transaction must happen
                                            # exactly once
Readonly my $ATP_CTL_EOMBIT     => 0x10;    # packet is end of message
Readonly my $ATP_CTL_STSBIT     => 0x08;    # send transaction status; upon
                                            # receipt by originator, resend
                                            # TReq packet
Readonly my $ATP_CTL_TREL_TMOUT => 0x07;

# TRel timeout periods for XO (exactly-once) transactions. Ignored by
# AppleTalk Phase1 implementations; I don't think this applies to anything
# except really, really old stuff.
Readonly our $ATP_TREL_30SEC     => 0x00;
Readonly our $ATP_TREL_1MIN      => 0x01;
Readonly our $ATP_TREL_2MIN      => 0x02;
Readonly our $ATP_TREL_4MIN      => 0x03;
Readonly our $ATP_TREL_8MIN      => 0x04;

# The maximum length of the ATP message body.
Readonly our $ATP_MAXLEN         => 578;
Readonly our $ATP_MAX_RESP_PKTS  => 8;
Readonly our $ATP_MAX_USERBYTES  => 4;

Readonly my $ATP_THR_RUNNING     => 1;
Readonly my $ATP_THR_NOT_STARTED => 0;
Readonly my $ATP_THR_ENDED       => -1;
Readonly my $ATP_POLL_INTERVAL   => 0.125;
Readonly my $ATP_TXID_LIMIT      => (2 ** 16);

# symbols to export
our @EXPORT = qw($ATP_MAXLEN $ATP_MAX_RESP_PKTS);
our @EXPORT_OK = qw($ATP_TREL_30SEC $ATP_TREL_1MIN $ATP_TREL_2MIN
                    $ATP_TREL_4MIN $ATP_TREL_8MIN);
our %EXPORT_TAGS = ( xo => [ qw($ATP_TREL_30SEC $ATP_TREL_1MIN $ATP_TREL_2MIN
                                $ATP_TREL_4MIN $ATP_TREL_8MIN) ] );

my $atp_header :shared = 'CCCS>a[4]a*';
my @atp_header_fields :shared = qw{ddp_type ctl bmp_seq txid userbytes data};
my %xo_timeouts :shared = (
    $ATP_TREL_30SEC => 30,
    $ATP_TREL_1MIN  => 60,
    $ATP_TREL_2MIN  => 120,
    $ATP_TREL_4MIN  => 240,
    $ATP_TREL_8MIN  => 480,
);

sub new { # {{{1
    my ($class, %sockopts) = @_;

    my $obj = bless {}, $class;

    my $shared = &share({});
    %{$shared} = (
        running     => $ATP_THR_NOT_STARTED,
        exit        => 0,
        last_txid   => int rand($ATP_TXID_LIMIT),
        conn_fd     => undef,
        conn_sem    => Thread::Semaphore->new(0),
        TxCB_list   => &share({}),
        RqCB_list   => &share({}),
        RqCB_txq    => &share([]),
        RqCB_sem    => Thread::Semaphore->new(0),
        RqFilters   => &share([]),
        TimedCBs    => &share([]),
        RspCB_list  => &share({}),
    );
    $obj->{Shared}          = $shared;
    my $thread = threads->create(\&thread_core, $shared, %sockopts);
    $obj->{Dispatcher}      = $thread;
    $shared->{conn_sem}->down();
    $obj->{Conn} = IO::Handle->new();
    if ($shared->{running} == $ATP_THR_RUNNING) {
        $obj->{Conn}->fdopen($shared->{conn_fd}, 'w');
    }
    else {
        $obj->{Dispatcher}->join();
    }
    $shared->{conn_sem}->up();

    if (exists $shared->{errno}) {
        $ERRNO = dualvar $shared->{errno}, $shared->{error};
    }
    return($shared->{running} == $ATP_THR_RUNNING ? $obj : undef);
} # }}}1

sub close { # {{{1
    my ($self) = @_;
    $self->{Shared}{exit} = 1;
    $self->{Dispatcher}->join();
    return;
} # }}}1

sub sockaddr { # {{{1
    my ($self) = @_;
    return $self->{Shared}{sockaddr};
} # }}}1

sub sockport { # {{{1
    my ($self) = @_;
    return $self->{Shared}{sockport};
} # }}}1

sub sockdomain { # {{{1
    my ($self) = @_;
    return $self->{Shared}{sockdomain};
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
    my %connect_args = ( Proto  => 'ddp',
                         Type   => SOCK_DGRAM,
                         %sockopts,
                       );
    my $conn = IO::Socket::DDP->new(%connect_args);
    if (!$conn || !$conn->sockaddr()) {
        $shared->{running}  = $ATP_THR_ENDED;
        $shared->{error}    = $ERRNO;
        $shared->{errno}    = int $ERRNO;
        $shared->{conn_sem}->up();
        return;
    }
    $shared->{running}      = $ATP_THR_RUNNING;

    $shared->{conn_fd}      = fileno $conn;
    $shared->{sockaddr}     = $conn->sockaddr();
    $shared->{sockport}     = $conn->sockport();
    #$shared->{peeraddr}     = $conn->peeraddr();
    #$shared->{peerport}     = $conn->peerport();
    $shared->{sockdomain}   = AF_APPLETALK;
    $shared->{conn_sem}->up();

    # Set up a poll object for checking out our socket. Also preallocate
    # several variables which will be used in the main loop.
    my $poll = IO::Poll->new();
    $poll->mask($conn, POLLIN);
    my ($txid, $txcb, $time, $from, $msg, %msgdata, $msgtype,
        $wants_sts, $is_eom, $seqno, $rqcb, $is_xo, $xo_tmout, $rspcb,
        $pktdata, $ctl_byte, $rv, $item, $port, $paddr, $addr,
        $txkey, $cb);

MAINLOOP:
    while ($shared->{exit} == 0) { # {{{2
        $time = gettimeofday();

        # Check for any timed callbacks.
        foreach my $rec (@{$shared->{TimedCBs}}) { # {{{3
            if (($rec->{last_called} + $rec->{period}) < $time) {
                no strict qw(refs);
                $cb = $rec->{callback};
                &{$cb->[0]}(@{$cb}[1 .. $#{$cb}], $time, $shared);
                $rec->{last_called} = $time;
            }
        } # }}}3

        # Okay, now we need to check existing outbound transactions for
        # status, resends, cleanups, etc...
        foreach my $scan_txid (keys %{$shared->{TxCB_list}}) { # {{{3
            $txcb = $shared->{TxCB_list}{$scan_txid};
            if (($time - $txcb->{stamp}) < $txcb->{tmout}) { next; }

            # We're past the indicated timeout duration for the
            # transaction, so now we have to decide its fate.
            if (!$txcb->{ntries}) {
                # Okay, you've had enough go-arounds. Time to put
                # this dog down.
                ${$txcb->{sflag}} = 0;
                delete $shared->{TxCB_list}{$scan_txid};
                $txcb->{sem}->up();
                next;
            }

            # Packet data needs to be resent. Sequence data will be updated
            # in the structure. We need to decrement the retry counter,
            # copy the updated sequence bitmap back into the packet data,
            # resend the packet, and update the retry counter.
            #print {\*STDERR} (caller 0)[3], "(): Resending TReq for txid ", $scan_txid, "\n";

            # -1 is special, it means "just keep trying forever"
            if ($txcb->{ntries} != -1) { $txcb->{ntries}-- }

            # Update packet data with new sequence bitmap.
            substr $txcb->{msg}, 2, 1, pack 'C', $txcb->{seq_bmp};

            $shared->{conn_sem}->down();
            send $conn, $txcb->{msg}, 0, $txcb->{target};
            $txcb->{stamp} = $time;
            $shared->{conn_sem}->up();
        } # }}}3

        # Check the XO transaction completion list as well.
        foreach my $scan_txkey (keys %{$shared->{RspCB_list}}) { # {{{3
            # If the transaction is past its keep-by, just delete it, nothing
            # more to be done on our end.
            $rspcb = $shared->{RspCB_list}{$scan_txkey};
            if (($time - $rspcb->{stamp}) >= $rspcb->{tmout}) {
                delete $shared->{RspCB_list}{$scan_txkey};
            }
        } # }}}3

        # Check the socket for incoming packets. If there's nothing, just
        # loop again.
        if (not $poll->poll($ATP_POLL_INTERVAL)) { next MAINLOOP; }

        # We've got something. Read in a potential packet. We know it's
        # never going to be larger than $DDP_MAXSZ.
        $shared->{conn_sem}->down();
        $from = recv $conn, $msg, $DDP_MAXSZ, 0;
        $shared->{conn_sem}->up();
        if (not defined $from) { next MAINLOOP; }

        # Unpack the packet into its constituent fields, and quietly
        # move on if its DDP type field is wrong.
        @msgdata{@atp_header_fields} = unpack $atp_header, $msg;
        if ($msgdata{ddp_type} != $DDPTYPE_ATP) { next MAINLOOP; }

        # Let's see what kind of message we've been sent.
        $msgtype = $msgdata{ctl} & $ATP_CTL_FNCODE;
        $txid = $msgdata{txid};

        # Get the requester source address and port and jam everything
        # together to make a transaction key, so separate requesters
        # can't stomp on one another's transaction requests.
        ($port, $paddr) = unpack_sockaddr_at($from);
        $addr = atalk_ntoa($paddr);
        $txkey = join q{/}, $addr, $port, $txid;

        if ($msgtype == $ATP_TReq) { # {{{3
            # Remote is asking to initiate a transaction with us.
            $is_xo      = $msgdata{ctl} & $ATP_CTL_XOBIT;
            $xo_tmout   = $msgdata{ctl} & $ATP_CTL_TREL_TMOUT;

            # Ignore a duplicate transaction request.
            if (exists $shared->{RqCB_list}{$txkey}) { next MAINLOOP; }

            # If there's an XO completion handler in place, then resend
            # whatever packets the peer indicates it wants.
            if (exists $shared->{RspCB_list}{$txkey}) { # {{{4
                $rspcb      = $shared->{RspCB_list}{$txkey};
                $rqcb       = $rspcb->{RqCB};
                $pktdata    = $rspcb->{RespData};

                foreach my $seq (0 .. $#{$pktdata}) {
                    # Check if the sequence mask bit corresponding to
                    # the sequence number is set.
                    if (not $rqcb->{seq_bmp} & (1 << $seq)) { next; }

                    $shared->{conn_sem}->down();
                    send $conn, $pktdata->[$seq], 0, $rqcb->{sockaddr};
                    $shared->{conn_sem}->up();
                }
                $rspcb->{stamp} = gettimeofday();
                next MAINLOOP;
            } # }}}4
            $rqcb = &share({});
            # Set up the transaction request block.
            %{$rqcb} = (
                txid            => $txid,
                is_xo           => $is_xo,
                xo_tmout_bits   => $xo_tmout,
                xo_tmout        => $xo_timeouts{$xo_tmout},
                seq_bmp         => $msgdata{bmp_seq},
                userbytes       => $msgdata{userbytes},
                data            => $msgdata{data},
                sockaddr        => $from,
            );

            # Try running the request block through any registered
            # transaction filter handlers before putting it on the
            # list for outside processing.
            foreach my $filter (@{$shared->{RqFilters}}) { # {{{4
                {
                    no strict qw(refs);
                    $rv = &{$filter->[0]}(@{$filter}[1 .. $#{$filter}], $rqcb);
                }
                # If the filter returned something other than undef,
                # it is (well, should be) an array ref containing
                # ATP user byte and payload blocks.
                if (not $rv) { next; }
                $pktdata = &share([]);
                foreach my $seq (0 .. $#{$rv}) {
                    $item = $rv->[$seq];
                    # Start borrowed code from RespondTransaction().
                    $ctl_byte = $ATP_TResp;
                    # last packet in provided set, so tell the
                    # requester that this is end of message...
                    if ($seq == $#{$rv}) { $ctl_byte |= $ATP_CTL_EOMBIT }
                    $msg = pack $atp_header, $DDPTYPE_ATP, $ctl_byte,
                            $seq, $txid, @{$item}{'userbytes', 'data'};
                    $pktdata->[$seq] = $msg;

                    if (not $rqcb->{seq_bmp} & (1 << $seq)) { next; }

                    # Okay, let's try registering the RspCB just
                    # before the last packet posts to the server...
                    if ($rqcb->{is_xo} && $seq == $#{$rv}) {
                        $rspcb = &share({});
                        %{$rspcb} = (
                            RqCB        => $rqcb,
                            RespData    => $pktdata,
                            tmout       => $rqcb->{xo_tmout},
                        );
                        $rspcb->{stamp}                 = gettimeofday();
                        $shared->{RspCB_list}{$txkey}   = $rspcb;
                    }

                    $shared->{conn_sem}->down();
                    send $conn, $msg, 0, $rqcb->{sockaddr};
                    $shared->{conn_sem}->up();
                    # End borrowed code from RespondTransaction().
                }
                next MAINLOOP;
            } # }}}4

            $shared->{RqCB_list}{$txkey} = $rqcb;
            push @{$shared->{RqCB_txq}}, $rqcb;
            $shared->{RqCB_sem}->up();
        } # }}}3
        elsif ($msgtype == $ATP_TResp) { # {{{3
            # Remote is responding to a transaction we initiated.

            # Ignore a transaction response to a transaction that we don't
            # know, either because we didn't initiate it, or because we
            # tried it enough times and gave up.
            if (not exists $shared->{TxCB_list}{$txid}) { next MAINLOOP; }

            # Get the transaction block, and grab a few bits of info
            # out of it to keep them at hand.
            $txcb       = $shared->{TxCB_list}{$txid};
            $is_eom     = $msgdata{ctl} & $ATP_CTL_EOMBIT;
            $wants_sts  = $msgdata{ctl} & $ATP_CTL_STSBIT;
            $seqno      = $msgdata{bmp_seq};

            # If the server says this packet is the end of the transaction
            # set, mask off any higher bits in the sequence bitmap.
            if ($is_eom) {
                $txcb->{seq_bmp} &= 0xFF >> ($ATP_MAX_RESP_PKTS - 1 - $seqno);
            }

            # If the sequence bit for this packet is already cleared,
            # just quietly move on.
            if (not $txcb->{seq_bmp} & (1 << $seqno)) { next MAINLOOP; }

            # Put data into the array of stored payloads.
            $txcb->{response}[$seqno] = &share([]);
            @{$txcb->{response}[$seqno]} =
                    @msgdata{'userbytes', 'data'};
            # Clear the corresponding bit in the sequence bitmap.
            $txcb->{seq_bmp} &= ~(1 << $seqno) & 0xFF;

            # If the sequence bitmap is now 0, then we've received
            # all the data we're going to.
            if (!$txcb->{seq_bmp}) { # {{{4
                ${$txcb->{sflag}} = 1;
                $txcb->{sem}->up();

                # If it was an XO transaction, we should send a TRel here.
                next MAINLOOP if !$txcb->{is_xo};

                #print {\*STDERR} (caller 0)[3], "(): Sending TRel for txid ", $txid, "\n";
                # Don't need to preserve the XO bits.
                substr $txcb->{msg}, 1, 1, pack 'C', $ATP_TRel;
                $shared->{conn_sem}->down();
                # Don't need to send the whole packet, just the type, ATP
                # control fields, and user bytes...
                send $conn, substr($txcb->{msg}, 0, 9), 0, $txcb->{target};
                $shared->{conn_sem}->up();
                delete $shared->{TxCB_list}{$txid};
                next MAINLOOP;
            } # }}}4

            # If the server wants an STS, or the sequence number is
            # high enough that it's not going up further but there are
            # still packets we need, then resend the request packet.
            next MAINLOOP if not $wants_sts and (not $txcb->{seq_bmp} or
                    ($txcb->{seq_bmp} >> $seqno));

            # Update packet data with new sequence bitmap.
            substr $txcb->{msg}, 2, 1, pack 'C', $txcb->{seq_bmp};

            $shared->{conn_sem}->down();
            send $conn, $txcb->{msg}, 0, $txcb->{target};
            $txcb->{stamp} = gettimeofday();
            $shared->{conn_sem}->up();
        } # }}}3
        elsif ($msgtype == $ATP_TRel) { # {{{3
            # Peer has sent us a transaction release message, so drop
            # the pending RspCB if one is present. I think we can
            # safely delete even if it's not there; saves us the time
            # of checking.
            delete $shared->{RspCB_list}{$txkey};
        } # }}}3
    } # }}}2
    $shared->{running} = $ATP_THR_ENDED;
    # If we reach this point, we're exiting the thread. Notify any pending
    # waiting calls that they've failed before we go away.
    foreach my $txcbi (values %{$shared->{TxCB_list}}) {
        ${$txcbi->{sflag}} = 0;
        $txcbi->{sem}->up();
    }
    # If someone's blocking in GetTransaction(), this will snap them out
    # of it...
    $shared->{RqCB_sem}->up();

    undef $shared->{conn_fd};
    CORE::close($conn);
    return;
} # }}}1

sub SendTransaction { # {{{1
    my ($self, %options) = @_;

    croak('UserBytes must be provided')
            if not exists $options{UserBytes};
    $options{Data} ||= q{};
    croak('ResponseLength must be provided')
            if not exists $options{ResponseLength};
    $options{ResponseStore} ||= *foo{SCALAR};
    croak('ResponseStore must be provided and be a scalar ref')
            if ref($options{ResponseStore}) ne 'SCALAR' and
                 ref($options{ResponseStore}) ne 'REF';
    $options{StatusStore} ||= *bar{SCALAR};
    croak('StatusStore must be provided and be a scalar ref')
            if ref($options{StatusStore}) ne 'SCALAR' and
                 ref($options{StatusStore}) ne 'REF';
    croak('Timeout must be provided') if not exists $options{Timeout};
    $options{NumTries} ||= -1;
    $options{PeerAddr} ||= undef;

    # Check a few parameters before we proceed.
    croak('Data size was infeasibly large')
            if length($options{Data}) > $ATP_MAXLEN;
    croak('Caller requested impossible number of response packets')
            if $options{ResponseLength} > $ATP_MAX_RESP_PKTS;
    croak('UserBytes block was too large')
            if length($options{UserBytes}) > $ATP_MAX_USERBYTES;
    return ESHUTDOWN() if $self->{Shared}{running} != $ATP_THR_RUNNING;

    # Set up the outgoing transaction request packet.
    my $ctl_byte = $ATP_TReq;
    if (exists $options{ExactlyOnce}) {
        $ctl_byte |= $ATP_CTL_XOBIT | $options{ExactlyOnce};
    }
    my $seq_bmp = 0xFF >> ($ATP_MAX_RESP_PKTS - $options{ResponseLength});

    my $txcb_queue = $self->{Shared}{TxCB_list};
    my $txid;
    # Okay, have to handle potential transaction ID collisions due to
    # wrapping...
    do {
        $txid = ++$self->{Shared}{last_txid} % $ATP_TXID_LIMIT;
    } while (exists $txcb_queue->{$txid});

    my $msg = pack $atp_header, $DDPTYPE_ATP, $ctl_byte, $seq_bmp, $txid,
            $options{UserBytes}, $options{Data};

    # Set up the transaction control block.
    my $ntries = $options{NumTries};
    my $txcb = &share({});
    %{$txcb} = (
                 msg        => $msg,
                 ntries     => $ntries == -1 ? $ntries : ($ntries - 1),
                 response   => &share([]),
                 seq_bmp    => $seq_bmp,
                 is_xo      => exists $options{ExactlyOnce},
                 tmout      => $options{Timeout},
                 sem        => Thread::Semaphore->new(0),
                 sflag      => &share($options{StatusStore}),
                 target     => $options{PeerAddr},
               );
    ${$options{ResponseStore}} = $txcb->{response};

    # Indicate this as when the transaction has started (have to do this
    # before we queue the TxCB)...
    $txcb->{stamp} = gettimeofday();

    # Seems that (at least on System 7?) transactions are processed 100%
    # linearly (no queuing), and a transaction sent before the previous
    # transaction's TRel goes through, the request gets ignored.
    while (scalar keys %{$self->{Shared}{TxCB_list}} > 1) {
        #print {\*STDERR} (caller 0)[3], "(): waiting for pending transactions to clear before submitting txid $txid\n";
        #print {\*STDERR} (caller 0)[3], "(): pending transactions:", join(', ', keys %{$self->{Shared}{TxCB_list}}), "\n";
        usleep(250);
    }

    # Register our transaction control block so the thread can see it,
    # since we have no idea how soon the response will come back from
    # who we're talking to.
    $txcb_queue->{$txid} = $txcb;

    # Send request packet.
    $self->{Shared}{conn_sem}->down();
    send $self->{Conn}, $msg, 0, $options{PeerAddr};
    $self->{Shared}{conn_sem}->up();

    return $txcb->{sem};
} # }}}1

sub GetTransaction { # {{{1
    my ($self, $do_block, $filter) = @_;

    # Get the ref for the queue of incoming transactions.
    my $rqcb_queue = $self->{Shared}{RqCB_txq};

    # Handle optionally blocking for a new transaction.
    if ($do_block) { $self->{Shared}{RqCB_sem}->down(); }

    foreach my $i (0 .. $#{$rqcb_queue}) {
        no strict qw(refs);
        # If no transaction filter was passed, or the transaction filter
        # returned true, grab the RqCB out of the queue, remove it from
        # the pending queue, and return it to the caller.
        if (!defined($filter) || &{$filter}($rqcb_queue->[$i])) {
            my $rqcb = $rqcb_queue->[$i];
            @{$rqcb_queue} = @{$rqcb_queue}[0 .. ($i - 1),
                    ($i + 1) .. $#{$rqcb_queue}];
            # If the caller asked to block to wait, restore the semaphore
            # count to where it should be.
            if ($do_block && $i > 0) {
                $self->{Shared}{RqCB_sem}->up($i - 1);
            }
            return $rqcb;
        }
        # Down the sem again, so that if we're at the last, we'll block
        # until another is enqueued.
        if ($do_block) { $self->{Shared}{RqCB_sem}->down(); }
    }
    # If we reach this point, the caller didn't ask to block *and* no
    # transactions matched (or none were in the waiting queue), so just
    # send back an undef.
    return;
} # }}}1

sub RespondTransaction { # {{{1
    my ($self, $rqcb, $resp_r) = @_;

    croak('$resp_r must be an array') if ref($resp_r) ne 'ARRAY';

    # If the transaction response is too big/small, just abort the whole
    # mess now.
    croak('Ridiculous number of response packets supplied')
            if scalar(@{$resp_r}) > $ATP_MAX_RESP_PKTS
                or scalar(@{$resp_r}) < 1;

    # Abort if the transaction ID that the caller indicated is unknown to us.
    my ($port, $paddr) = unpack_sockaddr_at($rqcb->{sockaddr});
    my $addr = atalk_ntoa($paddr);
    my $txkey = join q{/}, $addr, $port, $rqcb->{txid};
    croak() if not exists $self->{Shared}{RqCB_list}{$txkey};

    my $pktdata = &share([]);

    foreach my $seq (0 .. $#{$resp_r}) {
        croak('$resp_r->[' . $seq . '] was not a hash ref')
                if ref($resp_r->[$seq]) ne 'HASH';
        my $ctl_byte = $ATP_TResp;
        # last packet in provided set, so tell the requester that this is
        # end of message...
        if ($seq == $#{$resp_r}) { $ctl_byte |= $ATP_CTL_EOMBIT }
        my $msg = pack $atp_header, $DDPTYPE_ATP, $ctl_byte, $seq,
                $rqcb->{txid}, @{$resp_r->[$seq]}{'userbytes', 'data'};
        $pktdata->[$seq] = $msg;

        if (not $rqcb->{seq_bmp} & (1 << $seq)) { next; }

        # Okay, let's try registering the RspCB just before the last packet
        # posts to the server...
        if ($rqcb->{is_xo} && $seq == $#{$resp_r}) {
            my $rspcb = &share({});
            %{$rspcb} = (
                RqCB        => $rqcb,
                RespData    => $pktdata,
                tmout       => $rqcb->{xo_tmout},
            );
            $rspcb->{stamp}                      = gettimeofday();
            $self->{Shared}{RspCB_list}{$txkey}  = $rspcb;
        }

        $self->{Shared}{conn_sem}->down();
        send $self->{Conn}, $msg, 0, $rqcb->{sockaddr};
        $self->{Shared}{conn_sem}->up();
    }

    # Remove the transaction from the stored list.
    delete $self->{Shared}{RqCB_list}{$txkey};
    return;
} # }}}1

# The idea here is to be able to pass a subroutine that looks at the
# transaction block and, if it's known, handle the transaction without
# passing it on to transaction queue at all.
sub AddTransactionFilter { # {{{1
    my ($self, $filter) = @_;

    push @{$self->{Shared}{RqFilters}}, $filter;
    return;
} # }}}1

sub AddPeriodicCallback { # {{{1
    my ($self, $period, $callback) = @_;

    my $cb_rec = &share({});
    %{$cb_rec} = (
        callback    => $callback,
        period      => $period,
        last_called => 0,
    );
    push @{$self->{Shared}{TimedCBs}}, $cb_rec;
    return;
} # }}}1

1;
# vim: ts=4 fdm=marker

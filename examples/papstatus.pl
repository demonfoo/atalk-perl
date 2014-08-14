#!/usr/bin/env perl

use strict;
use warnings;

use Net::Atalk::PAP;
use Net::Atalk::NBP;
use Net::Atalk;
use Getopt::Long;
use English qw(-no_match_vars);

sub usage {
    print {*STDERR} 'Usage:  ', $PROGRAM_NAME,
            " [ -A address ] [ -p printername ]\n";
    exit 1;
}

my $printer_name;
my %sockparms;
GetOptions( 'p=s'   => \$printer_name,
            'A=s'   => sub { $sockparms{LocalAddr} = $_[1] },
            'h'     => \&usage );

usage() unless defined $printer_name;

my @tuples = NBPLookup($printer_name, 'LaserWriter', undef, exists $sockparms{LocalAddr} ? $sockparms{LocalAddr} : undef, 1);
if (not scalar @tuples) {
    printf {*STDERR} "Can't resolve \"\%s\"\n", $printer_name;
    exit 1;
}
my($host, $port) = @{$tuples[0]}[0,1];

my $papconn = Net::Atalk::PAP->new($host, $port, %sockparms);
my $status;
if ($papconn->PAPStatus(\$status)) {
    print substr($status, 1), "\n";
}
$papconn->close();

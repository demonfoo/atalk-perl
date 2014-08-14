#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use Net::Atalk::NBP;
use Getopt::Long;
use English qw(-no_match_vars);

my $maxents;
my $localaddr;

sub usage {
    print "Usage:\t", $PROGRAM_NAME,
            " [ -A address ] [ -r responses ] [ obj:type\@zone ]\n";
    exit 1;
}

GetOptions('A=s' => \$localaddr,
           'r=i' => \$maxents,
           'h'   => \&usage) || usage();

my ($host, $type, $zone) = qw(= = *);

usage() if scalar(@ARGV) > 1;
my ($target) = @ARGV;
if (defined $target) {
    ($host, $type, $zone) = $target =~
            m{^(.*?)(?::([\w\s\-]*|=))?(?:[@](\w*|[*]))?$}s;
}

foreach my $tuple (NBPLookup($host, $type, $zone, $localaddr, $maxents)) {
    printf "\%31s:\%-34s \%s:\%u\n", @{$tuple}[3,4,0,1];
}

# vim: ts=4 et ai

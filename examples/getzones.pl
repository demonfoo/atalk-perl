#!/usr/bin/env perl

use strict;
use warnings;
use diagnostics;

use Carp;
local $SIG{__WARN__} = \&Carp::cluck;

use Net::Atalk::ZIP;
use Getopt::Long;
use English qw(-no_match_vars);

sub usage {
    print {*STDERR} "usage:\t", $PROGRAM_NAME, " [-m | -l] [-v] [address]\n";
    exit 1;
}

my $zipcall = \&ZIPGetZoneList;
my ($myzoneflag, $localzonesflag, $verbose);
GetOptions( 'm' => sub {
            usage() if defined $localzonesflag;
            $zipcall = \&ZIPGetMyZone;
            $myzoneflag = 1;
        },
            'l' => sub {
            usage() if defined $myzoneflag;
            $zipcall = \&ZIPGetLocalZones;
            $localzonesflag = 1;
        },
            'v' => \$verbose,
            'h' => \&usage ) || usage();

my ($zonelist, $lastflag) = &{$zipcall}($ARGV[0], 0);
croak('Error sending ZIP request: ' . $ERRNO) if not $zonelist;
if (ref($zonelist) eq 'ARRAY') {
    foreach my $zone (@{$zonelist}) {
        if ($verbose) {
            my $zoneinfo = ZIPGetNetInfo($zone);
            print "Zone name:\t\t", $zoneinfo->{zonename}, "\n";
            print "Network number range:\t", $zoneinfo->{NetNum_start}, ' - ', $zoneinfo->{NetNum_end}, "\n";
            print "Multicast address:\t", $zoneinfo->{mcastaddr}, "\n";
            print "\n";
        }
        else {
            print $zone, "\n";
        }
    }
} else {
    print $zonelist, "\n";
}

# vim: ts=4 et ai

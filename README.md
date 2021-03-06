### Net::Atalk version 0.50

Net::Atalk is a collection of pure Perl modules, implementing interfaces to
several of the AppleTalk core protocols. Specifically, it includes
implementations of an [IO::Socket](http://perldoc.perl.org/IO/Socket.html) derivate for DDP raw socket access
(IO::Socket::DDP), implementations of the ATP and ASP protocol layers,
and implementations for resolving names via NBP, and getting zone
information via ZIP. Sample scripts are also included which implement
aecho, nbplkup and getzones tools in Perl, so if your system has AppleTalk
support, is running atalkd, and is configured correctly for AppleTalk
services, the tools will operate as the C-based alternatives from the
[netatalk](http://netatalk.sourceforge.net) distribution do. (Also verified functional on NetBSD and FreeBSD.)

This package is mainly intended for my [Perl AFP stack](http://github.com/demonfoo/afp-perl) (Net::AFP) to
be able to access AFP mounts via AppleTalk, but could potentially be
used to talk to any AppleTalk-based service, or write your own
AppleTalk-based service. I have not implemented ADSP support, as there's
nothing (as far as I know) that actually uses it. That said, there's
nothing _preventing_ someone from implementing it. I also intend to
implement a PAP client as well, but it's not complete yet.

This package does require a threaded Perl; the response and resend
handling wasn't really doable (at least that I could figure) without
running the receive dispatcher as a thread. On FreeBSD, you will need
to build a threaded Perl from ports; NetBSD, Mac OS X, and most Linux
distributions do so by default, so the normal packages work perfectly.


#### INSTALLATION

Building the package is pretty much the normal process as with any Perl
module.

```bash
perl Makefile.PL
make
make install
```


#### DEPENDENCIES

All dependencies are satisfied by the packages distributed with Perl.


#### COPYRIGHT AND LICENSE

Copyright © 2009-2016 Derrik Pates



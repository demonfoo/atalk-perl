#!/usr/bin/env perl

use ExtUtils::MakeMaker;
WriteMakefile(
	'NAME'		=> 'Net::Atalk',
	'VERSION_FROM'	=> 'lib/IO/Socket/DDP.pm',
	'EXE_FILES'	=>  [ 'examples/aecho.pl', 'examples/getzones.pl', 'examples/nbplkup.pl' ],
);


# Samba::DB Makefile.PL
# $Id$

use ExtUtils::MakeMaker;

WriteMakefile(
	NAME => 'Samba::DB',
	VERSION_FROM => 'lib/Samba/DB.pm',
	EXE_FILES => [
		"bin/smbdmp",
		"bin/smbdb",
		"bin/loadsmbdir",
		"bin/smbproc",
	],
	PREREQ_PM => {
		'DBD::SQLite' => 1.3, # tested against 1.35
		'YAML' => 0, # tested against 0.84
	}
);


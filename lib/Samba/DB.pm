
# Samba::DB
# =========
#
# $Id
#
# Samba::LogParser SQL-Backed usage database class.
#
#

# globals

package Samba::DB;
$VERSION = 1.0;

use warnings;
use strict;

use Carp;

use DBI;
use DBD::SQLite;

# sub predecls

sub new;
sub connect;

sub createdb;
sub begintxn;
sub insertrec;
sub updaterec;
sub endtxn;

# todo: smart-insert - e.g. replace existing records with update
#   ... this is good if e.g. still logged in records are lated updated

sub main;

# subs

sub new {
	my $class = shift;
	my $fname = shift;

	my $self = {};

	$self->{dburi} = undef;
	$self->{dbh} = undef;
	$self->{sth} = undef;

	if($fname) {
		Samba::DB::connect($self,$fname) or return undef;
	}

	bless $self,$class;

	return $self;
}

sub connect {
	my ($self,$fname) = @_;

	return undef unless $fname;

	my $dburi = "dbi:SQLite:$fname";
	my $dbh = DBI->connect($dburi);

	if(!$dbh) {
		carp "unable to connect to $dburi: $!\n";
		return undef;
	}

	# connection settings...
	$dbh->do('pragma journal_mode = truncate');

	$self->{dburi} = $dburi;
	$self->{dbh} = $dbh;

	return $dbh;
}

sub createdb {
	my $self = shift;

	my ($dbh,$sth);
	my $schema = join '', <DATA>;

	$dbh = $self->{dbh};

	if(!$dbh) {
		carp "createdb on unconnected object";
		return 1;
	}

	$sth = $dbh->prepare($schema);
	$sth->execute();

	return 0;
}

sub begintxn {
	my $self = shift;
        my $dbh = $self->{dbh};

        if(!$dbh) {
                carp "begintxn on unconnected object";
                return 1;
        }

        $dbh->do('begin transaction');
} 

sub insertrec {

	my ($self,$rec) = @_;
	my ($dbh,$sth);

	return undef unless $rec;

	$dbh = $self->{dbh};
	$sth = $self->{sth};

	if(!$sth) {
		$sth = $dbh->prepare("
			insert into smbdata values
			(?,?,?,?,?,?,?,?,?,?,?)
		");
		$self->{sth} = $sth;
	}

	$sth->bind_param(1, $rec->{in});
	$sth->bind_param(2, $rec->{out});
	$sth->bind_param(3, $rec->{shn});
	$sth->bind_param(4, $rec->{svc});
	$sth->bind_param(5, $rec->{rhn});
	$sth->bind_param(6, $rec->{rip});
	$sth->bind_param(7, $rec->{logname});
	$sth->bind_param(8, $rec->{uid});
	$sth->bind_param(9, $rec->{gid});
	$sth->bind_param(10, $rec->{pid});
	$sth->bind_param(11, $rec->{state});

	return $sth->execute();
}

sub endtxn {
	my $self = shift;
       	my $dbh = $self->{dbh};

        if(!$dbh) {
                carp "begintxn on unconnected object";
                return 1;
        }

        $dbh->do('commit');
}


1;
__DATA__

--
-- Samba::DB SQL Schema
-- created for sqlite3 databases
--
-- $Id$
--

create table smbdata (
        timein integer not null,
        timeout integer,
        svchost text not null,
	svcname text not null,
	clihost text not null,
	cliaddr text not null,
	logname text not null,
	uid integer not null,
	gid integer not null,
	pid integer not null,
	type text,
	primary key (timein,svchost,svcname,pid,cliaddr,logname)
);


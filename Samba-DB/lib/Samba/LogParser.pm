
# Samba::LogParser
#
# samba log parsing module - 
# generates samba service 'session' records
#
# $Id$

package Samba::LogParser;

use strict;
use warnings;

use Carp;
use Time::Local;

use YAML;

# sub predecls

sub new;
sub open;
sub sethost;
sub next;

sub _nextlogevt;
sub _dateconv;

sub main;
sub _dmpmain;
sub _procmain;

# subs

sub new {
	my $class = shift;
	my $file = shift;
	my $self = {};

	$self->{recs} = [];		# found records list

	# for '_nextlogevt' logic
	$self->{_logfh} = undef;	# logfile filehandle
	$self->{_dateconv} = 1;		# assume date conversion OK.

	# for 'next' logic
	$self->{_shn} = undef;		# server hostname (not 100% in logs)
	$self->{_ins} = {};		# currently logged-in sessions
	$self->{_pend} = [];		# pending records to be processed

	if($file) {
		Samba::LogParser::open($self,$file);
	}

	bless $self,$class;
	return $self;
}

sub open {
	my $self = shift;
	my $fn = shift;
	my $fh;

	if(!CORE::open( $fh, '<', $fn )) {
		carp "couldn't open file: $!\n";
		return undef;
	}

	$self->{_logfh} = $fh;
	return $fh;
}

sub sethost {
	my ($self,$shn) = @_;
	$self->{_shn} = $shn;
}

sub next {
	my $self = shift;
	my ($key,$rec) = undef;

	my $ins = $self->{_ins}; 	# key: rip:share
	my $pend = $self->{_pend};

	my $shn = $self->{_shn};
	$shn = 'Amnesiac' unless $shn;

	while(1) {

		my $evt = $self->_nextlogevt();

		if(!$evt) {
			($key,$rec) = each %{$ins};

			if($key) {
				$rec->{out} = 0;
				$rec->{state} = 'active';

				delete $ins->{$key};

				return $rec;
			}
			return undef; # no events, no remaining records 
		}

		my $rip = $evt->{rip};
		my $svc = $evt->{svc};
		$key = "$rip:$svc";

		my $type = $evt->{type};

		if ($type eq 'con') {

			$rec = {
				in => $evt->{date},
				out => undef,
				shn => $shn,
				rhn => $evt->{rhn},
				rip => $rip,
				svc => $svc,
				logname => $evt->{logname},
				uid => $evt->{uid},
				gid => $evt->{gid},
				pid => $evt->{pid}
			};

			# XXX: multiple rip:svc collisions possible
			$ins->{$key} = $rec;
			$self->{_ins} = $ins;

			next;
		}

		if ($type eq 'hup') {
			$rec = $ins->{$key};

			next unless $rec;

			$rec->{out} = $evt->{date};
			$rec->{state} = 'normal';

			delete $ins->{$key};
			$self->{_ins} = $ins;

			return $rec;
		}
	}
}

#
# log stream:
#
#   we need to interleave lines - log is "timestamp\nlogmsg\n";
#   (possibly multiple logmsgs... to be reviewed)
#
# of note / handled so far:
#
#   - open: amanda-pc (10.118.76.159) connect to service purcell initially 
#         as user amj10 (uid=46534, gid=990) (pid 26237)
#   - close: amanda-pc (10.118.76.159) closed connection to service purcell
#

sub _nextlogevt {

	my $self = shift;
	my $fh = $self->{_logfh};

	# date lines
	my $datestr;
	my $datelnrx = '\[(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})';

	# log lines
	my $conrx = '  (.+?) \((.*?)\).*?connect to service (.*?) initially'
		. ' as user (.*?) \(uid=(\d+), gid=(\d+)\) \(pid (\d+)\)';
	my $huprx = '  (.+?) \((.+?)\) closed connection to service (.+)';

	my $ret = {};

	while(<$fh>) {

		if ($_ =~ m:$datelnrx:) { # date lines
			$datestr = $self->_dateconv($1);

			# hmm : multi-events per date creates error?
			$ret->{date} = $datestr;
		}

		elsif ($_ =~ m:^  :) { # logging lines

			if($_ =~ m:$conrx:) {
				$ret->{type} = 'con';
				$ret->{rhn} = $1;
				$ret->{rip} = $2;
				$ret->{svc} = $3;
				$ret->{logname} = $4;
				$ret->{uid} = $5;
				$ret->{gid} = $6;
				$ret->{pid} = $7;

				return $ret;
			}

			if($_ =~ m:$huprx:) {
				$ret->{type} = 'hup';
				$ret->{rhn} = $1;
				$ret->{rip} = $2;
				$ret->{svc} = $3;

				return $ret;
			}

		}
		else {
			next; # is error? hmm
		}

	}
}

sub _dateconv { # dateconv timestring - assumes localtime

	my $self = shift;
	my $datestr = shift;

	return $datestr unless $self->{_dateconv};

	my ($Y,$m,$d,$H,$M,$S,$ns); # strftime(3) conventions += 'ns'

	# we don't yet handle:
	#   '(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2}).\d{6}';
	# - not all logs log this
	# - timelocal doesn't parse ns anyway

	my $timerx = '(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})';

	if($datestr =~ m@$timerx@) {
		($Y,$m,$d,$H,$M,$S) = ( $1, $2, $3, $4, $5, $6 );
		return timelocal($S,$M,$H,$d,($m-1),$Y);
	}
	else {
		carp "_dateconv recieved bogus timestring\n";
		return $datestr; 
	}
}

sub main {
	&_procmain(@_);
}

sub _dmpmain { # _nextlogevt()-based main loop (low-level/raw events)

	my $class = shift;

	if(scalar @_ < 1) {
		( my $app = $0) =~ s:.*/::;
		print "usage: $app filename\n";
		return 0;
	}

	my $lp = Samba::LogParser->new();

	foreach my $file (@_) {
		print "# file: $file\n";
		$lp->open($file);
		while (my $evt = $lp->_nextlogevt()) {
			print YAML::Dump $evt;
		}

	}

	return 0;

}

sub _procmain { # next()-based main loop (high-level/cooked events)

	my $class = shift;
	my $args = [];

	my $errexit = sub {
		( my $app = $0) =~ s:.*/::;
		print "usage: $app {hostname filename} ... \n";
		return 0;
	};

	if((scalar @_ < 1) || (scalar @_ % 2)) {
		return $errexit->();
	}
	
	while(my ($h,$f) = @_ ) { # and go
		shift @_;
		shift @_;

		my $lp = Samba::LogParser->new();
		
		$lp->sethost($h);
		$lp->open($f);

		while (my $evt = $lp->next()) {
			print YAML::Dump $evt;
		}
	}

	return 0;
}

1;
__DATA__
[2015/04/09 08:34:21.634446,  3] auth/auth.c:219(check_ntlm_password)
  check_ntlm_password:  Checking password for unmapped user [ADRICE]\[amj10]@[AMANDA-PC] with the new password interface
[2015/04/09 08:34:21.634505,  3] auth/auth.c:222(check_ntlm_password)
  check_ntlm_password:  mapped user is: [ADRICE]\[amj10]@[AMANDA-PC]
[2015/04/09 08:34:21.654217,  3] auth/auth.c:268(check_ntlm_password)
  check_ntlm_password: winbind authentication for user [amj10] succeeded
[2015/04/09 08:34:21.654258,  2] auth/auth.c:309(check_ntlm_password)
  check_ntlm_password:  authentication for user [amj10] -> [amj10] -> [amj10] succeeded
[2015/04/09 08:34:21.681522,  1] smbd/service.c:1114(make_connection_snum)
  amanda-pc (10.118.76.159) connect to service purcell initially as user amj10 (uid=46534, gid=990) (pid 26237)
[2015/04/09 08:49:19.387408,  1] smbd/process.c:457(receive_smb_talloc)
  receive_smb_raw_talloc failed for client 10.118.76.159 read error = NT_STATUS_CONNECTION_RESET.
[2015/04/09 08:49:19.387505,  1] smbd/service.c:1378(close_cnum)
  amanda-pc (10.118.76.159) closed connection to service purcell

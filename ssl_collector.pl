#!/usr/bin/perl

use Term::ANSIColor qw(:constants);
use threads;
use Thread::Semaphore;
use POSIX 'strftime';
use Time::HiRes qw ( setitimer ITIMER_REAL time );

if ($#ARGV != 0) {
	print "Usage: ssl_collector.pl <addresses_file>\n";
	exit;
}

my $start = time;
my $sem_nb = 10;

open (ADDR, $ARGV[0]);

unless ( -d "keys" ) {
	system "mkdir keys";
}

unless ( -d "certs" ) {
	system "mkdir certs";
}

unless ( -d "logs" ) {
	system "mkdir logs";
}

my $sem : shared = Thread::Semaphore->new($sem_nb);

my $addr_total = `wc -l $ARGV[0] | cut -d' ' -f1`;
$addr_total =~ s/\n//g;

my $addr_nb : shared = 0;
my $failed_nb : shared = 0;

sub show_status {
	my $duration = time - $start;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime $duration;
  my $hour = $hour - 1;
	my $pct = sprintf ("%0.2f", ($addr_nb * 100) / $addr_total);
	print "$addr_nb/$addr_total ($pct %) in $hour h $min m $sec s  -- $failed_nb failed\n";
};

$SIG{ALRM} = \&show_status;
setitimer(ITIMER_REAL, 2, 5);

while (<ADDR>) {
	chomp;
	$sem->down;
	threads->create (sub {
        my ($addr) = @_;
					system "echo \"\" | timeout 20 openssl s_client -connect $addr:443 -sess_out tmp_$addr.pem -ignore_critical -showcerts -CApath /etc/ssl/certs > $addr.log 2> logs/$addr.log ";
					if ($? != 0) {
            #print RED, "Something wrong happened with $addr, see $addr.log for more details\n", RESET;
						$failed_nb += 1;
					} else {
						system "openssl sess_id -in tmp_$addr.pem -cert > certs/$addr.pem 2>> logs/$addr.log";
						if ($? != 0) {
							#print RED, "Something wrong happened with $addr, see $addr.log for more details\n", RESET;
						} else {
							system "openssl x509 -in certs/$addr.pem -noout -pubkey > keys/$addr.pem 2>> logs/$addr.log";	
							if ($? != 0) {
								#print RED, "Something wrong happened with $addr, see $addr.log for more details\n", RESET;
							}
						}
					}
				$addr_nb += 1;
				system "rm -rf tmp_$addr.pem";
				$sem->up;
	}, $_);
}

#$sem->down($sem_nb);
if ( -e "tmp.pem" ) {
	system "rm tmp.pem";
}
close (ADDR);

foreach $thr (threads->list) { 
        # Don't join the main thread or ourselves 
        if ($thr->tid && !threads::equal($thr, threads->self)) { 
            $thr->join; 
        } 
    }

show_status();
print "See logs file for more details\n";

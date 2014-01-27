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
my $sem_nb = 20;

open (ADDR, $ARGV[0]);

unless ( -d "keys" ) {
	system "mkdir keys";
}

unless ( -d "certs" ) {
	system "mkdir certs";
}

my $sem : shared = Thread::Semaphore->new($sem_nb);

my $addr_total = `wc -l $ARGV[0] | cut -d' ' -f1`;
$addr_total =~ s/\n//g;

my $addr_nb : shared = 0;
my $failed_nb : shared = 0;

my $handshake_failed :shared = 0;
my $protocol_failed :shared = 0;

sub show_status {
	system "echo $ARGV[0] > .status";
  system "echo $addr_nb >> .status";
	system "echo $handshake_failed >> .status";
	system "echo $protocol_failed >> .status";
	my $duration = time - $start;
	my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime $duration;
  my $hour = $hour - 1;
	my $pct = sprintf ("%0.2f", ($addr_nb * 100) / $addr_total);
	my $remaining_time = ($addr_total - $addr_nb) * ($duration / $addr_nb);
	my ($sec2, $min2, $hour2, $mday2, $mon2, $year2, $wday2, $yday2, $isdst) = localtime $remaining_time;
	$hour2 -= 1;
	print "$addr_nb/$addr_total ($pct %) in $hour h $min m $sec s  -- $handshake_failed failed handshakes, $protocol_failed protocol errors  -- remaining time : ~ $hour2 h $min2 m $sec2 s\n";
};

if (-e ".status") {
	open(STATUS, ".status");
	chomp($f = <STATUS>);
	if ($f eq $ARGV[0]) {
		chomp($addr_nb = <STATUS>);
		chomp($handshake_failed = <STATUS>);
		chomp($protocol_failed = <STATUS>);
		close(STATUS);
		for ($i = 0; $i < $addr_nb; $i++) {
			chomp($t = <ADDR>);
		}
	}
}

$SIG{ALRM} = \&show_status;
setitimer(ITIMER_REAL, 2, 20);

$thr_nb = 0;
while (<ADDR>) {
    $thr_nb++;
    if ($thr_nb % 500 == 0) {
        print "Waiting for child threads to join\n";
        foreach $thr (threads->list) { 
            # Don't join the main thread or ourselves 
            if ($thr->tid && !threads::equal($thr, threads->self)) { 
                $thr->join; 
            } 
            print "thread ", $thr->tid, " joined\n";
        }
    }
	chomp;
	$sem->down;
	threads->create (sub {
        my ($addr) = @_;
				system "echo \"\" | timeout 20 openssl s_client -connect $addr:443 -sess_out tmp_$addr.pem -ignore_critical -showcerts -CApath /etc/ssl/certs > /dev/null 2> tmp_$addr.log";
				if ($? != 0) {
					system "grep \"protocol\" tmp_$addr.log > /dev/null 2> /dev/null";
					if ($? == 0) {
						$protocol_failed +=1;
					}
					system "grep \"handshake\" tmp_$addr.log > /dev/null 2> /dev/null";
					if ($? == 0) {
						$handshake_failed += 1;
					}
				} else {
					system "openssl sess_id -in tmp_$addr.pem -cert > certs/$addr.pem 2> tmp_$addr.log";
					if ($? != 0) {
						#print RED, "Something wrong happened with $addr, see $addr.log for more details\n", RESET;
					} else {
						system "openssl x509 -in certs/$addr.pem -noout -pubkey > keys/$addr.pem 2> tmp_$addr.log";	
						if ($? != 0) {
							#print RED, "Something wrong happened with $addr, see $addr.log for more details\n", RESET;
						}
					}
				}
				$addr_nb += 1;
				system "rm -rf tmp_$addr.pem tmp_$addr.log";
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

system "rm -rf .status";

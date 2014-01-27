#! /usr/bin/perl

use File::Basename;
use POSIX 'strftime';
use Time::HiRes qw ( setitimer ITIMER_REAL time );

my $start = time;

my $certs_total = `ls certs | wc -l | cut -d' ' -f1`;
$certs_total =~ s/\n//g;

my $certs_nb = 0;

sub show_status {
        my $duration = time - $start;
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime $duration;
  my $hour = $hour - 1;
        my $pct = sprintf ("%0.2f", ($certs_nb * 100) / $certs_total);
        my $remaining_time = ($certs_total - $certs_nb) * ($duration / $certs_nb);
        my ($sec2, $min2, $hour2, $mday2, $mon2, $year2, $wday2, $yday2, $isdst) = localtime $remaining_time;
        $hour2 -= 1;
        print "$certs_nb/$certs_total ($pct %) in $hour h $min m $sec s -- remaining time : ~ $hour2 h $min2 m $sec2 s\n";
};


$SIG{ALRM} = \&show_status;
setitimer(ITIMER_REAL, 2, 5);



unless (-d "certs_links") {
	system "mkdir certs_links";
}

$stat = 0;
if ($#ARGV == 0 && $ARGV[0] eq '--stat') {
	$stat = 1;
	unless (-d "certs_unique_by_subject") {
		system "mkdir certs_unique_by_subject";
	}
	unless (-d "certs_unique_by_subject/keys") {
		system "mkdir certs_unique_by_subject/keys";
	}
}


unless (-d "certs_doublons") {
	system "mkdir certs_doublons";
}

system "rm -rf moduli";

@files = <certs/*.pem>;
foreach $file (@files) {
	$certs_nb++;
	# Certificate
	$hash = `openssl x509 -noout -in $file -modulus 2> /dev/null | cut -d'=' -f2 | sha512sum | cut -d' ' -f1 2> /dev/null`;
	if ($? != 0) {
		next;
	}
	$t = `ls -l certs_links | grep $hash 2> /dev/null`;
	if ($t ne '') {
		unless (-e "certs_doublons/$hash") {
			$link = `readlink certs_links/$hash`;
			$filename = basename($link);
			$filename =~ s/\.pem//g;
			$filename =~ s/\n//g;
			#print "main IP = $filename, hash = $hash\n";
			system "echo $filename > certs_doublons/$hash";
		}
		$filename = basename($file);
		$filename =~ s/\.pem//g;
		$filename =~ s/\n//g;
		#print "new doublon IP = $filename, hash = $hash\n";
		system "echo $filename >> certs_doublons/$hash";
	} else {
		system "openssl x509 -noout -in $file -modulus 2> /dev/null | cut -d'=' -f2 >> moduli";
		system "ln -s ../$file certs_links/$hash > /dev/null 2> /dev/null";
	}
	

	if ($stat) {
		$hash2 = `openssl x509 -noout -in $file -hash 2> /dev/null`;
		if ($? != 0) {
			next;
		}
		$t = `ls -l certs_unique_by_subject | grep $hash2 2> /dev/null`;
		if ($t eq '') {
			system "ln -s ../$file certs_unique_by_subject/$hash2 > /dev/null 2> /dev/null";
			$t = `ls -l certs_unique_by_subject/keys | grep $hash 2> /dev/null`;
			if ($t eq '') {
				system "ln -s ../$file certs_unique_by_subject/keys/$hash > /dev/null 2> /dev/null";
			}
		}
	}
}

show_status();

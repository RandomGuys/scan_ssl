#!/usr/bin/perl

use Term::ANSIColor qw(:constants);

open (ADDR, $ARGV[0]);

unless ( -d "keys" ) {
	system "mkdir keys";
}

unless ( -d "certs" ) {
	system "mkdir certs";
}

while (<ADDR>) {
	chomp;
	print "Fetching $_...\n";
	system "echo \"\" | openssl s_client -connect $_:443 -sess_out tmp.pem > /dev/null 2> /dev/null";
	if ($? != 0) {
		print RED, "Something wrong happened with $_\n",RESET;
		next;
	}
	print "Storing certificate...\n";
	system "openssl sess_id -in tmp.pem -cert > certs/$_.pem";
	print "Storing key...\n";
	system "openssl x509 -in certs/$_.pem -noout -pubkey > keys/$_.pem";
	print GREEN,"$_ done!\n",RESET;
}

if ( -e "tmp.pem" ) {
	system "rm tmp.pem";
}
close (ADDR);

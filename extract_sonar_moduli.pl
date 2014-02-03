#! /usr/bin/perl
use POSIX 'strftime';
use Time::HiRes qw ( setitimer ITIMER_REAL time );
use Crypt::OpenSSL::X509;

my $start = time;

open(IN, $ARGV[0]);

$certs_total = `wc -l $ARGV[0] | cut -d' ' -f1`;
$certs_total =~ s/\n//g;

$i = 1;

sub show_status {
        my $duration = time - $start;
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime $duration;
  		my $hour = $hour - 1;
        my $pct = sprintf ("%0.2f", ($i * 100) / $certs_total);
        my $remaining_time = ($certs_total - $i) * ($duration / $i);
        my ($sec2, $min2, $hour2, $mday2, $mon2, $year2, $wday2, $yday2, $isdst) = localtime $remaining_time;
        $hour2 -= 1;
        print "$i/$certs_total ($pct %) in $hour h $min m $sec s -- remaining time : ~ $hour2 h $min2 m $sec2 s\n";
};


$SIG{ALRM} = \&show_status;
setitimer(ITIMER_REAL, 2, 20);


open(IN2, ">insert_certs.sql");
#print IN2 "SET @id = 0;";
#print IN2 "CREATE TRIGGER id_certs BEFORE INSERT ON certificats FOR EACH ROW SET @id = @id + 1;";
while(<IN>) {
	chomp;
	$content = $_;
	system "echo \"-----BEGIN CERTIFICATE-----\" > tmp.pem";
	system "echo \"$content\" | cut -d',' -f2 >> tmp.pem";
	system "echo \"-----END CERTIFICATE-----\" >> tmp.pem";
	$tmp =  `fold -w 64 tmp.pem`;
	system "echo \"$tmp\" > tmp.pem";
#	$modulus =  `openssl x509 -noout -in tmp.pem -modulus 2> /dev/null | cut -d'=' -f2`;
#	$modulus =~ s/\n//g;
	
	my $x509 = Crypt::OpenSSL::X509->new_from_file('tmp.pem');
	
	my $str = "INSERT INTO certificats VALUES (NULL" . ",";
	
	# Récupération de l'empreinte
	if ($x509->sig_alg_name == "sha1WithRSAEncryption") {
		$str = $str . "\"". $x509->fingerprint_sha1(). "\", ";
#		print IN2  "\"". $x509->fingerprint_sha1(). "\", ";
		print "OK Fing SHA :   "  . $x509->fingerprint_sha1() . "\n";
	} elsif ($x509->sig_alg_name == "md5WithRSAEncryption"){
		$str = $str . "\"". $x509->fingerprint_md5(). "\", ";
#		print IN2  "\"". $x509->fingerprint_md5(). "\", ";
		print "OK Fing MD5 :   "  . $x509->sfingerprint_md5() . "\"\n";
	} else {
		$str = $str . "\"inconnu\", ";
#		print IN2  "\"inconnu\", ";
		print "Fingerprint inconnu\n";
	}
	print "OK Signature algo :   "  . $x509->sig_alg_name . "\n";
	
	$str = $str ."\"". $x509->version. "\", ";
#	print IN2  "\"". $x509->version. "\", ";
	print "OK Version :  "  . $x509->version. "\n";

	$str = $str ."\"". $x509->serial. "\", ";
#	print IN2  "\"". $x509->serial. "\", ";
	print "OK Serial :   "  . $x509->serial. "\n";

	$str = $str ."\"". $x509->sig_alg_name. "\", ";
#	print IN2  "\"". $x509->sig_alg_name. "\", ";
	print "OK Algo name :   "  . $x509->sig_alg_name. "\n";
	
	$str = $str ."\"". $x509->issuer_name()->get_entry_by_type("CN") . "\", ";
#	print IN2  "\"". $x509->issuer_name()->get_entry_by_type("CN") . "\", ";
	print "OK Issuer CN : " .  $x509->issuer_name()->get_entry_by_type("CN") . "\n";

	$str = $str ."\"". $x509->notBefore() . "\", ";
#	print IN2  "\"". $x509->notBefore() . "\", ";
	print "OK Date début : " . $x509->notBefore() . "\n";

	$str = $str ."\"". $x509->notAfter() . "\", ";
#	print IN2  "\"". $x509->notAfter() . "\", ";
	print "OK Date fin : " . $x509->notAfter() . "\n";

	$str = $str ."\"". $x509->subject_name()->get_entry_by_type("CN") . "\", ";
#	print IN2  "\"". $x509->subject_name()->get_entry_by_type("CN") . "\", ";
	print "OK Subject CN : " .  $x509->subject_name()->get_entry_by_type("CN") . "\n";

	eval {
		$modulus =  `openssl x509 -noout -in tmp.pem -modulus 2> /dev/null | cut -d'=' -f2`;
		$modulus =~ s/\n//g;
		$str = $str ."\"". $modulus . "\", ";
	#	print IN2  "\"". $x509->pubkey() . "\", ";
		print "OK Clé publique : " . $modulus . "\n";
	} or do {
		print "erreur pubkey\n";
		next;
	};

	$str = $str . "\"". $x509->sig_alg_name . "\", ";
#	print IN2  "\"". $x509->sig_alg_name . "\", ";
	print "OK Nom algo : " . $x509->sig_alg_name . "\n";

	$str = $str ."NULL);" . "\n";
#	print IN2  "NULL);" . "\n";
	print IN2 $str;
	
#	pid				INT #si doublon : id du premier
	
	$i++;
}
close (IN2);
close(IN);

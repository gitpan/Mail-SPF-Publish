#!/usr/bin/perl

use strict;
use lib "../lib/";
use Mail::SPF::Publish;

my $spf = Mail::SPF::Publish->new( ttl => 3600, explicit_wildcards => 0, output_type => 'tinydns' );

$spf->mailserver( "mail_one", "mail1.example.com", "10.0.0.1", ttl => 14400 );
$spf->mailserver( "mail_two", "mail2.example.com", "10.0.0.2", ttl => 86400 );

$spf->domainservers( "example.com", [ "mail_one", "mail_two" ], ttl => 14400, deny => 'softdeny' );

print $spf->output(explicit_wildcards => 1, output_type => 'bind4');

print "\n\n";

$spf->domainincludes( "example.com", [ "example.net:10", "example.org:20" ], ttl => 7200 );

print $spf->output();

#!/usr/bin/perl

use strict;
use lib "../lib/";
use Mail::SPF::Publish;

my $spf = Mail::SPF::Publish->new( explicit_wildcards => 0, output_type => 'tinydns' );

$spf->mailserver( "mail_one", "mail1.example.com", "10.0.0.1" );
$spf->mailserver( "mail_two", "mail2.example.com", "10.0.0.2" );

$spf->domainservers( "example.com", "mail_one", "mail_two" );

print $spf->output(explicit_wildcards => 1, output_type => 'bind9');

print "\n\n";

$spf->domainincludes( "example.com:10", "example.net", "example.org" );

print $spf->output();

#!/usr/bin/perl

use strict;
use lib "../lib/";
use Mail::SPF::Publish qw(:all);

spf_mailserver( "mail_one", "mail1.example.com", "10.0.0.1" );
spf_mailserver( "mail_two", "mail2.example.com", "10.0.0.2" );

spf_domainservers( "example.com", "mail_one", "mail_two" );

spf_fix_recursion();

print spf_output_bind9();

print "\n\n";

print spf_output_tinydns();

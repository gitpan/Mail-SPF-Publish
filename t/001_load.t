# -*- perl -*-

# t/001_load.t - check module loading and create testing directory

use Test::More tests => 2;

BEGIN { use_ok( 'Mail::SPF::Publish' ); }

my $spf = Mail::SPF::Publish->new();

$spf && ok("Object creation successful: $spf\n");


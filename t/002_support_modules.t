use Test::More tests => 8;

BEGIN {
  use_ok( 'Mail::SPF::Publish::domain' );
  use_ok( 'Mail::SPF::Publish::record' ); 
}

my $root_domain = Mail::SPF::Publish::domain->new( undef, '' );

ok( $root_domain, 'Root domain creation' );

my $domain = $root_domain->descend( 'www.example.com' );

ok( $domain, 'Subdomain creation' );

my $records = $domain->records();

ok( $records, 'Subdomain record fetch' );


my $record = Mail::SPF::Publish::record->new( class => 'IN', type => 'A', ttl => 1234, value => '127.0.0.1' );

ok( $record, 'Record creation' );

push @$records, $record;

my $bind_output = $root_domain->bind_out();

ok( $bind_output =~ m/^www\.example\.com\.\s+1234\s+IN\s+A\s+127\.0\.0\.1$/, 'Bind9 Output' );

my $tinydns_output = $root_domain->tinydns_out();

ok( $tinydns_output =~ m/^\+www\.example\.com:127\.0\.0\.1:1234$/, 'Tinydns Output' );


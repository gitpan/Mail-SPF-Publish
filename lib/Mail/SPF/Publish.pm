
package Mail::SPF::Publish;
use strict;

BEGIN {
	use Exporter ();
	use vars qw ($VERSION @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);
	$VERSION     = '0.00_01';
	@ISA         = qw (Exporter);
	#Give a hoot don't pollute, do not export more than needed by default
	@EXPORT      = qw ();
	@EXPORT_OK   = qw (spf_mailserver spf_domainservers spf_domainset spf_fix_recursion spf_output_bind9 spf_output_tinydns);
	%EXPORT_TAGS = ( all => [qw(spf_mailserver spf_domainservers spf_fix_recursion spf_output_bind9 spf_output_tinydns)]);
}

use Mail::SPF::Publish::domain;
use Mail::SPF::Publish::record;

my $nets = Mail::SPF::Publish::domain->new(undef, ''); #has no parent, trap later

my $aliases = {};
my $deny = 'softdeny';
my $ttl = 3600;


=head1 NAME

Mail::SPF::Publish - Assist in the creation of DNS records for the SPF standard. 

=head1 SYNOPSIS

  use Mail::SPF::Publish
 
  spf_mailserver( "mail_one", "mail1.example.com", "10.0.0.1" );
  spf_mailserver( "mail_two", "mail2.example.com", "10.0.0.2" );

  spf_domainservers( "example.com", "mail_one", "mail_two" );

  spf_fix_recursion();

  print spf_output_bind9();


=head1 DESCRIPTION

This module and it's associated sample code are intended to be used to generate DNS records (tinydns and BIND9 so far) for SPF, including any explicit wildcard recursion if necessary. The interface right now is /very/ questionable as this has not been proofread by anyone yet. Please be warned that this module may change considerable or not at all before first release.


=head1 USAGE

=head2 spf_mailserver

 Usage     : spf_mailserver( alias, hostname, address );
 Purpose   : Defines a mail server alias, and creates the SPF records for HELO lookups.
 Returns   : Nothing yet
 Arguments : alias    - string alias for this entry
             hostname - fully qualified domain name this mail server, and hostname name supplied at HELO phase.
	     address  - network address of this mail server

=cut

sub spf_mailserver ($$$) {
  my ($alias, $hostname, $address) = @_;

  $aliases->{$alias} = [ $hostname, $address ];

  my @numbers = split /\./, $address;
  my @names = ((reverse split( /\./, $hostname )), '_smtp_client');
  
  {
    my $domain = descend( [@names, '*'], $nets);
    my $records = $domain->records();
    
    push @$records, Mail::SPF::Publish::record->new(
      ttl => $ttl,
      class => 'IN',
      type => 'TXT',
      value => 'spf=deny',
    );
  }
  
  push @names, ('in-addr', @numbers);

  {
    my $domain = descend( \@names, $nets);
    my $records = $domain->records();

    push @$records, Mail::SPF::Publish::record->new(
      ttl => $ttl,
      class => 'IN',
      type => 'TXT',
      value => 'spf=allow',
    );
  }  
}

=head2 spf_domainservers

 Usage     : spf_domainservers( domain, alias, ... )
 Purpose   : Create SPF records to indicate that servers identified by 'alias, ...' are allowed to send from 'domain'. All others are subject to the policy defined by spf_softhard()
 Returns   : Nothing Yet
 Arguments : domain - Domain name to which you are adding mail servers to for SPF record generation.
             alias, ... - List of server aliases, defined with the spf_mailserver() function.

=cut

sub spf_domainservers ($@) {
  my ($domain, @aliases) = @_;

  my @base = ((reverse split( /\./, $domain )), '_smtp_client');

  {
    my $domain = descend( [@base, '*'], $nets);
    my $records = $domain->records();

    push @$records, Mail::SPF::Publish::record->new(
      ttl => $ttl,
      class => 'IN',
      type => 'TXT',
      value => 'spf=' . $deny,
    );
  }

  foreach my $alias (@aliases) {
    my ($hostname, $address) = @{$aliases->{$alias}};
    my @numbers = split /\./, $address;    
    my @names = (@base, 'in-addr', @numbers);
    my $domain = descend( \@names, $nets );
    my $records = $domain->records();

    push @$records, Mail::SPF::Publish::record->new(
      ttl => $ttl,
      class => 'IN',
      type => 'TXT',
      value => 'spf=allow',
    );
  }
}

=head2 spf_fix_recursion

 Usage     : spf_fix_recursion()
 Purpose   : Creates explicit wildcard domains to allow a workaround for RFC 1034 compliant name servers
 Returns   : Nothing yet
 Argument  : None

=cut

sub spf_fix_recursion {
  fix_recursion( $nets );
}

sub fix_recursion {
  my ($domain) = @_;
  my $subdomains = $domain->domains();

  foreach my $subdomain (values %{$subdomains}) {
    next if( $subdomain->name() eq '*' );
    next if( get_spf( $domain ) );

    fix_recursion( $subdomain );
  }

  foreach my $record (@{$domain->records()}) {
    return if ( ( uc( $record->type() ) eq 'TXT' ) && ( $record->value() =~ m/^spf=/ ) );
  }

  unless( exists $subdomains->{'*'} && get_spf( $subdomains->{'*'} ) ) {
    return unless $domain->parent();
    my $nearest_spf_domain = find_nearest_spf( $domain->parent() );
    
    if( $nearest_spf_domain && $nearest_spf_domain->name() eq '*' ) {
      $subdomains->{'*'} = Mail::SPF::Publish::domain->new($domain, '*');
      my $record = get_spf( $nearest_spf_domain );
      push @{$subdomains->{'*'}->records()}, $record->clone();
    }
  }
}

sub spf_output_bind9 {
  $nets->bind_out();
}

sub spf_output_tinydns {
  $nets->tinydns_out();
}

sub spf_ttl (;$) {
  $ttl = $_[0] if (@_ > 0);
  return $ttl;
}

sub spf_deny (;$) {
  $deny = $_[0] if (@_ > 0);
  return $deny;
}

# Subroutines after here should undoubtably be more private

sub find_nearest_spf {
  my $domain = shift;

  my $subdomains = $domain->domains();

  foreach my $subdomain ( values %$subdomains ) {
    return $subdomain if get_spf($subdomain);
  }

  return unless( $domain->parent() );

  return find_nearest_spf( $domain->parent() );
}


sub get_spf {
  my $domain = shift;
 
  foreach my $record ( @{$domain->records()} ) {
    if( (uc( $record->type() ) eq 'TXT') && ($record->value() =~ m/^spf=/) ) {
      return $record;
    }
  }
  return undef;
}

sub descend {
  my $names = shift;
  my $parent = shift;

  return $parent unless (@$names);

  my $domains = $parent->domains();
  my $name = shift @$names;
  
  $domains->{$name} = Mail::SPF::Publish::domain->new($parent, $name)
    unless( exists $domains->{$name} );

  return descend( $names, $domains->{$name} );
}

1;
__END__


=head1 BUGS

Undoubtably some, tests are the next thing on the list to be written.

=head1 SUPPORT

Please contact the author with any comments or questions.

=head1 AUTHOR

Jonathan Steinert
hachi@cpan.org

=head1 COPYRIGHT

This program is free software; you can redistribute
it and/or modify it under the same terms as Perl itself.

The full text of the license can be found in the
LICENSE file included with this module.


=head1 SEE ALSO

http://spf.pobox.com/
Mail::SPF::Query
perl(1).

=cut

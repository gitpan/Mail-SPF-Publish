package Mail::SPF::Publish;
use strict;

use vars qw ($VERSION);
$VERSION     = '0.00_02';

use Mail::SPF::Publish::domain;
use Mail::SPF::Publish::record;

=head1 NAME

Mail::SPF::Publish - Assist in the creation of DNS records for the SPF standard. 

=head1 SYNOPSIS

  use Mail::SPF::Publish
 
  my $spf = Mail::SPF::Publish->new( ttl => 86400 );

  $spf->mailserver( "mail_one", "mail1.example.com", "10.0.0.1" );
  $spf->mailserver( "mail_two", "mail2.example.com", "10.0.0.2" );

  $spf->domainservers( "example.com", "mail_one", "mail_two" );

  $spf->domainincludes( "example.com", "example.net", "example.org" );

  print $spf->output( output_type => 'bind9' );


=head1 DESCRIPTION

This module and it's associated sample code are intended to be used to generate DNS records (tinydns and BIND9 so far) for SPF, including any explicit wildcard recursion if necessary. The interface right now is /very/ questionable as this has not been proofread by anyone yet. Please be warned that this module may change considerable or not at all before first release.


=head1 USAGE

=head2 new

=over

=item Usage

  my $spf = Mail::SPF::Publish->new();

=item Purpose

Creates a new SPF publishing module

=item Returns

The object it just created.

=item Arguments

=over

=item explicit_wildcards

Sets whether explicit wildcards are to be generated (Default: 1)

=item output_type

Sets the type of output you want, currently only two possible values: 'bind9' 
and 'tinydns'. (Default: 'bind9' )

=item ttl

Sets the ttl for all entires in the generated DNS heirarchy. (Default: 86400)

=item deny

Sets the deny string for SPF deny records on dommains (but not on individual machines). Logical values would be 'deny' or 'softdeny'. (Default: 'deny')

=back

=back

=cut

sub new {
  my $class = shift;
  my %args = @_;

  my $self = bless {
    aliases => {},
    domains => {},
    options => {
      deny => 'deny',
      ttl => 86400,
      output_type => 'bind9',
      explicit_wildcards => 1, 
    },
  }, (ref( $class ) || $class);

  my $options = $self->{options};

  $options->{output_type} = $args{output_type} if exists( $args{output_type} );
  $options->{explicit_wildcards} = $args{explicit_wildcards} if exists( $args{explicit_wildcards} );
  $options->{ttl} = $args{ttl} if exists( $args{ttl} );
  $options->{deny} = $args{deny} if exists( $args{deny} );

  return $self;
}

=head2 mailserver

=over

=item Usage

  $spf->mailserver( alias, hostname, address );

=item Purpose

Defines a mail server alias, and creates the SPF records for HELO lookups.

=item Returns

Nothing yet

=item Arguments

=over 

=item alias

string alias for this entry

=item hostname

fully qualified domain name this mail server, and hostname name supplied at HELO phase.

=item address

network address of this mail server (currently only an ipv4 address is
supported)

=back

=back

=cut

sub mailserver ($$$$) {
  my $self = shift;
  my ($alias, $hostname, $address) = @_;

  $self->{aliases}->{$alias} = [ $hostname, $address ];
}

=head2 domainservers

=over

=item Usage

  $spf->domainservers( domain, alias, ... )

=item Purpose

Create SPF records to indicate that servers identified by 'alias, ...' are allowed to send from 'domain'. All others are subject to the policy defined by softhard()

=item Returns

Nothing Yet

=item Arguments

=over

=item domain

Domain name to which you are adding mail servers to for SPF record generation.

=item alias, ... 

List of server aliases, defined with the mailserver() function.

=back

=back

=cut

sub domainservers ($$@) {
  my $self = shift;
  my ($domain, @aliases) = @_;

  $self->{domains}->{$domain} = \@aliases;
}

=head2 domainincludes

=over

=item Usage

  $spf->domainincludes( source_domain, domain, ... )

=item Purpose

Creates 'SPFinclude=source_domain' TXT records in each of the supplied domains to cause a recursive lookup for allowed sending servers.

=item Arguments

=over

=item source_domain

Domain which each of the domain entries will point to with an SPFinclude record.

=item domain, ...

List of domains which SPFinclude records will be created in. This list will probably be of uncreated domains

=back

=item Notes

If you are using this module to maintain the SPF records for both the source_domain and any of the other domains; you may wish to use domainservers() instead for these records. While domainincludes() does simplify the creation of multiple domains, it increases the number of DNS lookups that must be made. Put otherwise, in order to minimize traffic you should use this call as little as possible.

=back

=cut

sub domainincludes ($$@) {
  my $self = shift;
  my ($source, @domains) = @_;

  $self->{includes}->{$source} = \@domains;
}

=head2 output

=over

=item Usage

  print $spf->output();

or

  my $output = $spf->output();

=item Purpose

Compiles domain information collected by all the previous method calls, and produces an output suitable for use in the specified (or default, if you didn't specify) name server.

=item Returns

A multi-line string containing the output.

=item Arguments

This function will take an 'explicit_wildcards' and 'output_type' option as documented under the new() function. The supplied values will be used to override the default provided in the new() function for the current run only.

=back

=cut

sub output ($;@) {
  my $self = shift;
  my @args = @_;

  $self->{nets} =  Mail::SPF::Publish::domain->new( undef, '' ), #has no parent, things shouldn't recurse upwards past here

  my %options = ( %{$self->{options}}, @args );

  while (my ($key, $value) = each %{$self->{aliases}}) {
    my ($hostname, $address) = @$value;
    my $rnumbers = _rnumbers( $address );
    $self->_create_spf_record( "*._smtp_client.$hostname", 'deny' );
    $self->_create_spf_record( "$rnumbers.in-addr._smtp_client.$hostname", 'allow' );
  }

  while (my ($key, $value) = each %{$self->{domains}}) {
    $self->_create_spf_record( "*._smtp_client.$key", $self->{deny} );

    foreach my $alias (@$value) {
      my ($hostname, $address) = @{$self->{aliases}->{$alias}};
      my $rnumbers = _rnumbers( $address );
      $self->_create_spf_record( "$rnumbers.in-addr._smtp_client.$key", 'allow' );
    }
  }

  while (my ($source, $includes) = each %{$self->{includes}}) {
    foreach my $include (@$includes) {
      $self->_create_spf_include( "*._smtp_client.$include", $source );
    }
  }

  _fix_recursion( $self->{nets} )
    if ($options{explicit_wildcards});
  
  $self->{nets}->output( $options{output_type} );
}

####################################################################
# Private subroutines

sub _rnumbers {
  my @return;
  foreach my $number (@_) {
    push @return, join( '.', reverse( split( /\./, $number ) ) );
  }
  if (wantarray()) {
    return @return;
  }
  eles {
    return $return[0];
  }
}

sub _find_nearest_spf {
  my $domain = shift;

  my $subdomains = $domain->domains();

  foreach my $subdomain ( values %$subdomains ) {
    return $subdomain if _get_spf($subdomain);
  }

  return unless( $domain->parent() );

  return _find_nearest_spf( $domain->parent() );
}

sub _get_spf {
  my $domain = shift;
 
  foreach my $record ( @{$domain->records()} ) {
    if( (uc( $record->type() ) eq 'TXT') && ($record->value() =~ m/^spf=/) ) {
      return $record;
    }
  }
  return undef;
}

sub _fix_recursion {
  my ($domain) = @_;
  my $subdomains = $domain->domains();

  foreach my $subdomain (values %{$subdomains}) {
    next if( $subdomain->name() eq '*' );
    next if( _get_spf( $domain ) );

    _fix_recursion( $subdomain );
  }

  foreach my $record (@{$domain->records()}) {
    return if ( ( uc( $record->type() ) eq 'TXT' ) && ( $record->value() =~ m/^spf=/ ) );
  }

  unless( exists $subdomains->{'*'} && _get_spf( $subdomains->{'*'} ) ) {
    return unless $domain->parent();
    my $nearest_spf_domain = _find_nearest_spf( $domain->parent() );
    
    if( $nearest_spf_domain && $nearest_spf_domain->name() eq '*' ) {
      $subdomains->{'*'} = Mail::SPF::Publish::domain->new($domain, '*');
      my $record = _get_spf( $nearest_spf_domain );
      push @{$subdomains->{'*'}->records()}, $record->clone();
    }
  }
}

sub _create_spf_record {
  my $self = shift;
  my ($basename, $policy) = @_;

  my $domain = $self->{nets}->descend( $basename );
  
  my $record;
  if ($record = _get_spf( $domain )) {
    $record->ttl( $self->{ttl} );
    $record->class( 'IN' );
    $record->type( 'TXT' );
    $record->value( 'spf=' . $policy );
  }
  else {
    my $records = $domain->records();
    push @$records, Mail::SPF::Publish::record->new(
      ttl => $self->{options}->{ttl},
      class => 'IN',
      type => 'TXT',
      value => "spf=$policy",
    );
  }
}

sub _create_spf_include {
  my $self = shift;
  my ($basename, $policy) = @_;

  my $domain = $self->{nets}->descend( $basename );
  my $records = $domain->records();
  push @$records, Mail::SPF::Publish::record->new(
    ttl => $self->{options}->{ttl},
    class => 'IN',
    type => 'TXT',
    value => "SPFinclude=$policy" );
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

=cut

package Mail::SPF::Publish;
use strict;

use vars qw ($VERSION);
$VERSION     = '0.02';

use Net::CIDR;
use Mail::SPF::Publish::domain;
use Mail::SPF::Publish::record;

=head1 NAME

Mail::SPF::Publish - Assist in the creation of DNS records for the SPF standard. 

=head1 SYNOPSIS

  use Mail::SPF::Publish
 
  my $spf = Mail::SPF::Publish->new( ttl => 86400 );

    # Basic form
  $spf->mailserver( "mail_one", "mail1.example.com", [ "10.0.0.1" ] );

    # Multi-homed mail server
  $spf->mailserver( "mail_two", "mail2.example.com", [ "10.0.0.2", "192.168.0.1" ] );

    # Multi-homed mail server with CIDR style notation
  $spf->mailserver( "mail_three", "mail3.example.com", [ "10.0.0.8/30", "192.168.8.0/29" ] );

  $spf->domainservers( "example.com", [ "mail_one", "mail_two", "mail_three" ], default => 'softdeny');

  $spf->domainincludes( "myvanity.com", [ "myisp.com", "myschool.edu" ], ttl => 86400 );

  print $spf->output( format => 'bind4' );


=head1 DESCRIPTION

This module and its associated sample code are intended to
be used to generate DNS zone files for SPF under tinydns and
bind4-9, including any explicit wildcard recursion if
necessary. Most people will want to use the supplied scripts
for automatic generation of a zone, 'autospf' and
'spf2zone'.

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

=item format

Sets the type of output you want, currently only two possible values: 'bind4' 
and 'tinydns'. (Default: 'bind4' )

=item ttl

Sets the ttl for all entires in the generated DNS heirarchy. (Default: 86400)

=item default

Sets the default response for domains (but not on individual
machines).  You may set 'deny', 'softdeny', or
'accept'. (Default: 'deny')  Please don't set 'accept'.

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
      default => 'deny',
      ttl => 86400,
      format => 'bind4',
      explicit_wildcards => 1, 
    },
  }, (ref( $class ) || $class);

  my $options = $self->{options};

  $options->{format} = $args{format} if exists( $args{format} );
  $options->{explicit_wildcards} = $args{explicit_wildcards} if exists( $args{explicit_wildcards} );
  $options->{ttl} = $args{ttl} if exists( $args{ttl} );
  $options->{default} = $args{default} if exists( $args{default} );

  $options->{explicit_wildcards} = 0 if $args{output_type} eq "tinydns";

  return $self;
}

=head2 mailserver

=over

=item Usage

  $spf->mailserver( alias, hostname, addresslist, options );

=item Purpose

Defines a mail server alias, and creates the SPF records for HELO lookups.

=item Arguments

=over 

=item alias

string alias for this entry

=item hostname

fully qualified domain name this mail server, and hostname name supplied at HELO phase.

=item addresslist

arrayref of network address of this mail server (currently only ipv4 addresses are
supported, CIDR notation is optional.)

=back

=back

=cut

sub mailserver ($$$$;@) {
  my $self = shift;
  my ($alias, $hostname, $addresses, %options) = @_;
  my @addresses;

  if (ref $addresses eq 'ARRAY') {
    foreach my $address (@$addresses) {
      push @addresses, _check_and_cidrize( $address );
    }
  } else {
    push @addresses, _check_and_cidrize( $addresses );
  }
  
  $self->{aliases}->{$alias} = [ $hostname, \@addresses, \%options ];
}

=head2 domainservers

=over

=item Usage

  $spf->domainservers( domain, aliaslist, options )

=item Purpose

Create SPF records to indicate that servers identified by I<aliaslist> are allowed to send from I<domain>.

=item Arguments

=over

=item domain

Domain name to which you are adding mail servers to for SPF record generation.

=item aliaslist

Arrayref of server aliases, defined with the mailserver() function.

=item options

Option list to override default options, and those specified in new().

=back

=back

=cut

sub domainservers ($$@) {
  my $self = shift;
  if (ref $_[1] eq 'ARRAY') {
    my ($domain, $aliases, %options) = @_;
    $self->{domains}->{$domain} = [$aliases, \%options];
  } else {
    my ($domain, @aliases) = @_;
    my %options;
    $self->{domains}->{$domain} = [\@aliases, \%options];
  }
}

=head2 domainincludes

=over

=item Usage

  $spf->domainincludes( my_domain, other_domain_list, options )

=item Purpose

Creates 'SPFinclude=other_domain' TXT records for my_domain;
this allows my_domain to designate mailservers belonging to
other_domain.

=item Arguments

=over

=item my_domain

Domain under our control.

=item other_domain_list

Arrayref of domains which SPFinclude records will point to.
These domains are not under our control, but we want to
designate their servers.

=back

=item Notes

If the other_domains are under your control, use
domainservers() to create full-fledged entries for them
directly; this improves query time and saves traffic.

=back

=cut

sub domainincludes ($$@) {
  my $self = shift;
  if (ref $_[1] eq 'ARRAY') {
    my ($mydomain, $domains, %options) = @_;
    $self->{includes}->{$mydomain} = [$domains, \%options];
  } else {
    my ($mydomain, @domains) = @_;
    my %options;
    $self->{includes}->{$mydomain} = [\@domains, \%options];
  }
}

=head2 output

=over

=item Usage

  print $spf->output( options );

or

  my $output = $spf->output( options );

=item Purpose

Compiles domain information collected by all the previous method calls, and produces an output suitable for use in the specified (or default, if you didn't specify) name server.

=item Returns

A multi-line string containing the output.

=item Arguments

This function will take an I<explicit_wildcards> and I<format> option as documented under the new() function. The supplied values will be used to override the default provided in the new() function for the current call only.

=back

=cut

sub output ($;@) {
  my $self = shift;
  my @args = @_;

  $self->{nets} =  Mail::SPF::Publish::domain->new( undef, '' ), #has no parent, things shouldn't recurse upwards past here

  my %global_options = ( %{$self->{options}}, @args );

  while (my ($key, $value) = each %{$self->{aliases}}) {
    my ($hostname, $addresses, $alias_options) = @$value;
    my $options = {%global_options, %$alias_options};
    foreach my $address (_colapse_numbers( @$addresses )) {
      my $rnumbers = _rnumbers( $address );
      $self->_create_spf_record( "*._smtp_client.$hostname", 'deny', $options ); # always deny for mailservers.
      $self->_create_spf_record( "$rnumbers.in-addr._smtp_client.$hostname", 'allow', $options );
    }
  }

  while (my ($domain, $value) = each %{$self->{domains}}) {
    my ($aliases, $domain_options) = @$value;
    my $options = {%global_options, %$domain_options};
    
    {
      my $options = {%global_options, %$domain_options};
      $self->_create_spf_record( "*._smtp_client.$domain", $options->{default}, $options );
    }

    my @numbers;
    
    foreach my $alias (@$aliases) {
      my ($hostname, $addresses, $alias_options) = @{$self->{aliases}->{$alias}};
      push @numbers, @$addresses;
    }
      
    foreach my $number (_colapse_numbers( @numbers )) {
      my $rnumber = _rnumbers( $number );
      $self->_create_spf_record( "$rnumber.in-addr._smtp_client.$domain", 'allow', $options );
    }
  }

  while (my ($mydomain, $value) = each %{$self->{includes}}) {
    my ($includes, $include_options) = @$value;
    my $options = {%global_options, %$include_options};
    foreach my $include (@$includes) {
      $self->_create_spf_include( "*._smtp_client.$mydomain", $include, $options );
    }
  }

  _fix_recursion( $self->{nets} )
    if ($global_options{explicit_wildcards});
  
  $self->{nets}->output( $global_options{format} );
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

  return if (_get_spf( $domain ));

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
  my ($basename, $policy, $options) = @_;

  my $domain = $self->{nets}->descend( $basename );
  
  my $record;
  if ($record = _get_spf( $domain )) {
    $record->ttl( $options->{ttl} );
    $record->class( 'IN' );
    $record->type( 'TXT' );
    $record->value( 'spf=' . $policy );
  }
  else {
    my $records = $domain->records();
    push @$records, Mail::SPF::Publish::record->new(
      ttl => $options->{ttl},
      class => 'IN',
      type => 'TXT',
      value => "spf=$policy",
    );
  }
}

sub _create_spf_include {
  my $self = shift;
  my ($basename, $policy, $options) = @_;

  my $domain = $self->{nets}->descend( $basename );
  my $records = $domain->records();
  push @$records, Mail::SPF::Publish::record->new(
    ttl => $options->{ttl},
    class => 'IN',
    type => 'TXT',
    value => "SPFinclude=$policy" );
}

sub _colapse_numbers {
  my @cidr_list;
  foreach my $address (@_) {
    @cidr_list = Net::CIDR::cidradd( $address, @cidr_list );
  }
  my @return_list;
  foreach my $address (Net::CIDR::cidr2octets( @cidr_list )) {
    unless ($address =~ m/^\d+\.\d+\.\d+\.\d+$/) {
      $address .= '.*';
    }
    push @return_list, $address;
  }
  
  return @return_list;
}

sub _check_and_cidrize {
  my $address = $_[0];
  if ($address =~ m/^\d+\.\d+\.\d+\.\d+$/) {
    $address .= '/32';
    return $address;
  }
  elsif ($address =~ m/^\d+\.\d+\.\d+\.\d+\/\d{0,2}/) {
    return $address;
  } else {
    die( "Invalid ipv4 address: $address\n" );
  }
}

1;
__END__

=head1 BUGS

Entering anything besides IPv4 addresses into address lists may throw an error, or may just mangle the output.

Undoubtably others.

=head1 SUPPORT

Send a message to subscribe-spf-discuss@v2.listbox.com.

See also http://spf.pobox.com/

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

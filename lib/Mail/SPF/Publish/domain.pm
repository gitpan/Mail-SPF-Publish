package Mail::SPF::Publish::domain;

sub new {
  my $class = shift;
  my $self = bless {
    domains => {},
    records => [],
    parent => $_[0],
    name => $_[1],
  }, (ref $class || $class);
}

sub domains {
  my $self = shift;
  $self->{domains} = $_[0] if( @_ > 0 );
  return $self->{domains};
}

sub records {
  my $self = shift;
  $self->{records} = $_[0] if( @_ > 0 );
  return $self->{records};
}

sub parent {
  my $self = shift;
  $self->{parent} = $_[0] if( @_ > 0);
  return $self->{parent};
}

sub name {
  my $self = shift;
  $self->{name} = $_[0] if( @_ > 0);
  return $self->{name};
}

sub fullname {
  my $self = shift;
  my ($fullname) = @_;

  $fullname .= $self->name();
  my $parent = $self->parent();

  if( defined( $parent ) ) {
    $fullname .= '.';
    return $parent->fullname( $fullname );
  }
  else {
    return $fullname;
  }
}

sub bind_out {
  my $self = shift;
  my $subdomains = $self->domains();
  my $records = $self->records();

  my $output;

  if( @$records ) {
    foreach my $record (@$records) {
      my $value = ( uc($record->type()) eq 'TXT' ? '"' . $record->value() . '"' : $record->value() );
#      printf( "%50s\t%s\t%s\t%s\t%s\n", $self->fullname(), $record->ttl(), $record->class(), $record->type(), $value );
      $output .= sprintf( "%s\t%s\t%s\t%s\t%s\n", $self->fullname, $record->ttl(), $record->class(), $record->type(), $value );
    }
  }

  foreach my $name ( sort keys %{$subdomains} ) {
    my $subdomain = $subdomains->{$name};
    $output .= $subdomain->bind_out();
  }
  return $output;
}

sub tinydns_out {
  my $self = shift;
  my $subdomains = $self->domains();
  my $records = $self->records();

  my $output;

  if( @$records ) {
    foreach my $record (@$records) {
      if (uc( $record->type() ) eq 'TXT') {
        $output .= "'";
      }
      elsif (uc( $record->type() ) eq 'A') {
        $output .= "+";
      }
      my $fullname = $self->fullname();
      $fullname =~ s/.$//; # This is such a dirty hack, somebody hurt me.
      $output .= $fullname . ":" . $record->value() . ":" . $record->ttl() . "\n";
    }
  }

  foreach my $name ( sort keys %{$subdomains} ) {
    my $subdomain = $subdomains->{$name};
    $output .= $subdomain->tinydns_out();
  }
  return $output;
}

1;

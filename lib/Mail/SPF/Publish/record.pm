package Mail::SPF::Publish::record;

sub new {
  my $class = shift;
  my %options = @_;

  $options{ttl} = undef unless( exists $options{ttl} );
  $options{class} = undef unless( exists $options{class} );
  $options{type} = undef unless( exists $options{type} );
  $options{value} = undef unless( exists $options{value} );
  
  my $self = bless {
    ttl => $options{ttl},
    class => $options{class},
    type => $options{type},
    value => $options{value},
  }, ( ref $class || $class );
  return $self;
}

sub clone {
  my $self = shift;
  my $newself = bless {%$self}, ref $self;
  return $newself;
}

sub ttl {
  my $self = shift;
  $self->{ttl} = $_[0] if( @_ > 0 );
  return $self->{ttl};
}

sub class {
  my $self = shift;
  $self->{class} = $_[0] if( @_ > 0 );
  return $self->{class};
}

sub type {
  my $self = shift;
  $self->{type} = $_[0] if( @_ > 0 );
  return $self->{type};
}

sub value {
  my $self = shift;
  $self->{value} = $_[0] if( @_ > 0 );
  return $self->{value};
}

1;

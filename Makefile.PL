use ExtUtils::MakeMaker;

WriteMakefile(
  NAME		=> "Mail::SPF::Publish",
  VERSION_FROM	=> "lib/Mail/SPF/Publish.pm",
  AUTHOR	=> 'Jonathan Steinert (hachi@cpan.org)',
  ABSTRACT_FROM	=> "lib/Mail/SPF/Publish.pm",
  EXE_FILES	=> [ 'scripts/spf2zone', 'scripts/autospf' ],
  PREREQ_PM	=> {
    Net::CIDR => 0,
  },
  dist => {
    COMPRESS	=> "gzip -9",
  },
);
  

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME		=> "Mail::SPF::Publish",
  VERSION_FROM	=> "lib/Mail/SPF/Publish.pm",
  AUTHOR	=> 'Jonathan Steinert (hachi@cpan.org)',
  ABSTRACT_FROM	=> "lib/Mail/SPF/Publish.pm",
  dist => {
    COMPRESS	=> "gzip -9",
  },
);
  

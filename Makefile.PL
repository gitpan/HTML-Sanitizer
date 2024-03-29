use 5.006;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'HTML::Sanitizer',
    'VERSION_FROM'	=> 'Sanitizer.pm', # finds $VERSION
    'PREREQ_PM'		=> {
	HTML::TreeBuilder => 0,
    }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'Sanitizer.pm', # retrieve abstract from module
       AUTHOR     => 'David Nesting <david@fastolfe.net>') : ()),
);

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

use Test::More tests => 4;
BEGIN { use_ok('HTML::Sanitizer') };

#########################

sub despace ($) {
	local ($_) = @_;
	s/>\s*/>/mg; s/\s*\&/\&/mg;
	s/^\s*//; s/\s*$//;
	return $_;
}

# Basic Operation

my $safe = new HTML::Sanitizer;

# ----------------------------------------
ok($safe, "new HTML::Sanitizer");

# Set up a set of rules that we can use everywhere:

$safe = new HTML::Sanitizer (
	p     => 1,
	'*'   => undef,
);

# CPAN#2992

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>unsafe</p><script
)),    '<p>unsafe</p>&lt;script',	"HTML/XML entities");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p attr_ok="test>unsafe</p>
)),    '&lt;p attr_ok=&quot;test&gt;unsafe&lt;/p&gt;',	"HTML/XML entities with incomplete tag");


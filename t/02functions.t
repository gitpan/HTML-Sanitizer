# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

use Test::More tests => 11;
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
is(despace $safe->filter_xml_fragment(qq(
	<p>content</p>
)),    '',	"default should be filtered");

$safe->permit('p', 'i');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content</p><em>content</em>
)),    '<p>content</p>',	"'permit' function");

$safe->ignore('em');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content</p><em>content</em>
)),    '<p>content</p>content',	"'ignore' function");

$safe->deny('p');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content one</p><i>content two</i>
)),    '<i>content two</i>',	"'deny' function");

$safe->deny_only('i');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content one</p><i>content two</i>
)),    '<p>content one</p>',	"'deny_only' function");

$safe->ignore_only('p');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content one</p><i>content two</i>
)),    'content one<i>content two</i>',	"'ignore_only' function");

$safe->permit_only('p');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content one</p><i>content two</i>
)),    '<p>content one</p>',	"'permit_only' function");

# ----------------------------------------
is(despace $safe->filter_xml(qq(
	<p>content one</p><i>content two</i>
)),    '<html><body><p>content one</p></body></html>',	"'filter_xml' function");

# ----------------------------------------
is(despace $safe->filter_html(qq(
	<p>content one</p><i>content two</i>
)),    '<html><body><p>content one</body></html>',	"'filter_html' function");

# ----------------------------------------
is(despace $safe->filter_html_fragment(qq(
	<p>content one</p><i>content two</i>
)),    '<p>content one',				"'filter_html_fragment' function");


# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

use Test::More tests => 23;
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
	div   => 0,
	span  => undef,
	b     => HTML::Element->new('strong'),
	i     => HTML::Element->new('em', attr => 'new_value'),
	u     => HTML::Element->new('address')->push_content('new content'),
	sup   => HTML::Element->new('sub')->push_content(''),
	a     => {
		attr1 => 1,
		attr2 => 0,
		attr3 => qr/ok_value/,
		attr4 => sub { s/sub_value/new_value/ },
	},
	'_'   => {
		attr_ok  => 1,
		attr_bad => undef,
		'*'      => undef,
	},
	'*'   => undef,	# strip for now
);


# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content p</p>
)),    '<p>content p</p>',	"'permit' rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p attr_ok="attr value">content p</p>
)),    '<p attr_ok="attr value">content p</p>',	"'permit' rule, checking OK attributes");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p attr_bad="attr value">content p</p>
)),    '<p>content p</p>',	"'permit' rule, checking bad attributes");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p attr_unk="attr value">content p</p>
)),    '<p>content p</p>',	"'permit' rule, checking unknown attributes");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><div>content div</div>
)),    '<p>ok</p>content div',	"'ignore' rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><div>content div</div><span>content span</span>
)),    '<p>ok</p>content div',	"'deny' rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><b>content b</b>
)),    '<p>ok</p><strong>content b</strong>',	"HTML::Element rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><i attr="old_value">content i</i>
)),    '<p>ok</p><em attr="new_value">content i</em>',	"HTML::Element rule, attribute overlay");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><i attr_ok="attr value" attr="old_value">content i</i>
)),    '<p>ok</p><em attr="new_value" attr_ok="attr value">content i</em>',	
	"HTML::Element rule, attribute overlay with existing OK attribute");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><i attr_bad="attr value" attr="old_value">content i</i>
)),    '<p>ok</p><em attr="new_value">content i</em>',	
	"HTML::Element rule, attribute overlay with existing bad attribute");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><sup>content sup</sup>
)),    '<p>ok</p><sub></sub>',	
	"HTML::Element rule with empty replacement content");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>ok</p><u>content u</u>
)),    '<p>ok</p><address>new content</address>',	
	"HTML::Element rule with replacement content");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a>content a</a>
)),    '<a>content a</a>',	"Attribute rules imply tag permit");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr1="attr value">content a</a>
)),    '<a attr1="attr value">content a</a>',	"Attribute OK rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr2="attr value">content a</a>
)),    '<a>content a</a>',	"Attribute deny rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr3="xyz ok_value xyz">content a</a>
)),    '<a attr3="xyz ok_value xyz">content a</a>',	"Attribute OK regex rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr3="xyz bad_value xyz">content a</a>
)),    '<a>content a</a>',	"Attribute failed regex rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr4="xyz sub_value xyz">content a</a>
)),    '<a attr4="xyz new_value xyz">content a</a>',	"Attribute OK code rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<a attr4="xyz bad_value xyz">content a</a>
)),    '<a>content a</a>',	"Attribute failed code rule");

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content p</p><blockquote attr4="xyz bad_value xyz">content blockquote</blockquote>
)),    '<p>content p</p>',	"Unknown element should be stripped");

$safe->ignore('*');

# ----------------------------------------
is(despace $safe->filter_xml_fragment(qq(
	<p>content p</p><blockquote attr4="xyz bad_value xyz">content blockquote</blockquote>
)),    '<p>content p</p>content blockquote',	"Unknown element should be removed with child elements promoted");


# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl 1.t'

#########################

use Test::More tests => 9;
BEGIN { use_ok('HTML::Sanitizer') };

#########################

my $evil_html = '
   <html><body>
      <a href="javascript:alert()">Some link text</a>
      <a href="http://www.example.com/" title="Test">Some link text</a>
      <strong>Strong!</strong>
      <em>Bad!</em>
      <img src="http://www.example.com/">
      <p>A paragraph.</p>
   </body></html>
';

my $safe = new HTML::Sanitizer;

ok($safe, "new HTML::Sanitizer");

$safe->permit_only('em');

ok($safe->filter_as_html_fragment($evil_html) =~ m~^\s*<em>Bad!</em>\s*$~, "filter_as_html_fragment");

$safe->permit(a => { href => qr/^http:/, title => 1 }, 'p');

ok($safe->filter_as_xml_fragment($evil_html) =~ m~^\s*<a>Some link text</a>\s*<a href="http://www.example.com/" title="Test">Some link text</a>\s*<em>Bad!</em>\s*<p>A paragraph.</p>\s*$~, "filter_as_xml_fragment") or

diag($safe->filter_as_xml_fragment($evil_html));

ok($safe->filter_as_xml($evil_html) =~ m~^\s*<html>\s*<body><a>Some link text</a>\s*<a href="http://www.example.com/" title="Test">Some link text</a>\s*<em>Bad!</em>\s*<p>A paragraph.</p>\s*</body>\s*</html>\s*$~, "filter_as_xml_fragment") or
diag($safe->filter_as_xml($evil_html));

$safe = new HTML::Sanitizer;

$safe->deny_only('*' => [ 'style' ]);

$evil_html = '<p style="xyz">A paragraph.</p>';

is($safe->filter_as_xml_fragment($evil_html), "<p>A paragraph.</p>\n", "deny_only");

sub valid_test {
	return $_[2] eq 'ok_value';
}

$safe->permit_only('*' => { id => \&valid_test });

is($safe->filter_as_xml_fragment("<p id='ok_value'>OK</p><p id='bad_value'>BAD</p>"),
	"<p id=\"ok_value\">OK</p>\n<p>BAD</p>\n", "coderef filters");

# CPAN#2992
is($safe->filter_as_html_fragment("<img src='javascript:alert(1)'"), "&lt;img src='javascript:alert(1)'",
	"HTML entities");

# I hate writing tests.

$safe->permit_only(qw/ strong em /);
$safe->{preserve_children} = 1;

ok($safe->filter_as_html_fragment("<p>One<em>Two<strong>Three</strong>Four<x>-and-a-half</x></p>Five") =~
	m!One<em>Two<strong>Three</strong>Four-and-a-half</em>\s*Five!, "Filtering of preserved children");

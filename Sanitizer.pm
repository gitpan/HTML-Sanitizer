package HTML::Sanitizer;

use HTML::TreeBuilder;
use strict;
use warnings;
use Carp;
use HTML::Entities;

BEGIN {
	our $VERSION = 0.04;
	use constant DEBUG => 0;

	if (DEBUG) {
		use Data::Dumper;
	}
};

sub debug { print STDERR @_ if DEBUG }

sub new {
	my $pkg = shift;

	my $self = {
		_rules => ref($_[0]) ? shift() : { @_ },
	};

	bless $self, ref($pkg) || $pkg;
}

sub array2hash {
	my $x = shift;

	if (ref($x) eq 'ARRAY') {
		my $a;
		foreach (@{$x}) {
			$a->{$_} = 1;
		}
		$x = $a;
	}

	return $x;
}

sub permit {
	my $self = shift;

	while (@_) {
		my $element = shift;
		my $attrs = shift;

		$self->{_rules}->{$element} ||= {};

		if (UNIVERSAL::isa($attrs, "HTML::Element")) {
			$self->{_rules}->{$element} = $attrs;
		} 

		elsif (ref $attrs) {
			$attrs = array2hash($attrs);
			foreach (keys %{$attrs}) {
				$self->{_rules}->{$element}->{$_} = $attrs->{$_};
			}
		} 

		elsif (defined $attrs) {
			unshift(@_, $attrs);
		}
	}
}

sub _deny {
	my $with_what = shift;
	my $self = shift;

	while (@_) {
		my $element = shift;
		my $attrs = shift;

		if (ref $attrs) {
			croak "Attribute list for deny/ignore must be an arrayref" unless ref($attrs) eq 'ARRAY';

			foreach (@{$attrs}) {
				$self->{_rules}->{$element}->{$_} = $with_what;
			}
			next;
		} 
		elsif (defined $attrs) {
			unshift(@_, $attrs);
		}

		$self->{_rules}->{$element} = $with_what;
	}
}

sub deny   { _deny(undef, @_); }
sub ignore { _deny(0, @_); }
	
sub permit_only {
	my $self = shift;

	$self->{_rules} = {'*' => undef};
	$self->permit(@_);
}

sub deny_only {
	my $self = shift;

	$self->{_rules} = {'*' => {'*' => 1 }};
	$self->deny(@_);
}

sub ignore_only {
	my $self = shift;

	$self->{_rules} = {'*' => {'*' => 1 }};
	$self->ignore(@_);
}

sub filter_xml {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	return $tree->as_XML;
}

sub filter_xml_fragment {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	my $body = $tree->find_by_tag_name('body');
	$body ||= $tree;
	return join("", map { ref() ? $_->as_XML : $_ } $body->content_list);
}

sub filter_html {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	return $tree->as_HTML;
}

sub filter_html_fragment {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	my $body = $tree->find_by_tag_name('body');
	$body ||= $tree;
	return join("", map { ref() ? $_->as_HTML : $_ } $body->content_list);
}

sub _filter {
	my $self = shift;
	my $data = shift;

	if (DEBUG) {
		print STDERR "Filter: " . Dumper($self->{_rules}), "\n";
	}

	my $tree = new HTML::TreeBuilder;
	#	$tree->p_strict(1);
	$tree->parse($data);
	$tree->eof;

	carp 'Could not parse document' unless $tree;

	$self->sanitize_tree($tree) if $tree;

	return $tree;
}

sub sanitize_tree {
	my $self = shift;
	my $tree = shift;

	local($_);

	my $rules = $self->{_rules};

	$rules->{html} ||= 1;	# We need these
	$rules->{body} ||= 1;

	debug "      tree=$tree\n";

	foreach my $child ($tree->content_refs_list) {
		if (ref($$child)) {
			my $tag = lc $$child->tag;
			debug "Examining tag $tag\n";

			if (defined $rules->{$tag}) {
				if ($rules->{$tag}) {
	#				debug "  Tag has a rule: " . Dumper($rules->{$tag}) . "\n";
	
					$self->sanitize_attributes($$child);
	
					if (ref($rules->{$tag}) eq 'CODE') {
						unless ($rules->{$tag}->($$child)) {
							next if $self->_filter_child($$child);
						}
					}
	
					elsif (ref($rules->{$tag}) eq 'HTML::Element') {
						_replace_element($child, $rules->{$tag});
					}
	
				} 

				else {
					debug "  False rule found, bringing children up\n";
					$self->sanitize_tree($$child);
#					$self->sanitize_tree($_) for grep { ref } $$child->content_list;
					$$child->replace_with_content->delete;
				} 
			} 
			
			elsif (!exists $rules->{$tag} && defined $rules->{'*'}) {
				if ($rules->{'*'}) {
					debug "  Tag has no rule, but there's a default rule\n";
	
					$self->sanitize_attributes($$child);
					if (ref($rules->{'*'}) eq 'CODE') {
						unless ($rules->{'*'}->($$child)) {
							next if $self->_filter_child($$child);
						}
					}
	
					elsif (ref($rules->{'*'}) eq 'HTML::Element') {
						_replace_element($child, $rules->{'*'});
					}
	
				} 

				else {
					debug "  False default rule found, bringing children up\n";
					$self->sanitize_tree($$child);
#					$self->sanitize_tree($_) for grep { ref } $$child->content_list;
					$$child->replace_with_content->delete;
				} 
			}
	
			else {
				debug "  No/undef rule found, defaulting to deny\n";
				$$child->delete;
				next;
				#next if $self->_filter_child($$child);
			}

			debug "  $tag is ok\n";	
				
			$self->sanitize_tree($$child) if $child;
		} 
		else {
			$$child = encode_entities($$child);
		}
	}
}

sub _replace_element {
	my ($old, $rule) = @_;

	my $new = $rule->clone;
	debug "  $$old to be replaced by $new\n";
	$new->push_content($$old->detach_content)
		unless $new->content_list;

	foreach ($$old->all_attr_names) {
		$new->attr($_, $$old->attr($_)) unless defined($new->attr($_));
	}

	my @content = $new->content_list;
	if (@content == 1 && !ref($content[0]) && $content[0] eq '') {
		$new->delete_content;
	}

	$$old->replace_with($new);
}

#sub _filter_child {
#	my ($self, $child) = @_;
#
#	debug "  filtering tag " . $child->tag . "\n";
#	if ($self->{preserve_children}) {
#		$self->sanitize_tree($_) for grep { ref } $child->content_list;
#		$child->replace_with_content->delete;
#		return 0;
#	} 
#	else {
#		$child->delete;
#		return 1;
#	}
#}

sub sanitize_attributes {
	my ($self, $child) = @_;
	my $tag = lc $child->tag;

	foreach my $attr ($child->all_external_attr_names) {
		$attr = lc $attr;
		debug "    Checking attribute <$tag $attr>\n";

		my $r;
		ATTR_SEARCH: for my $o ($tag, "_", "*") {
			if (ref $self->{_rules}->{$o}) {
				for my $i ($attr, '*') {
					if (exists($self->{_rules}->{$o}->{$i})) {
						debug "      found match in $o/$i";
						$r = $self->{_rules}->{$o}->{$i};
						last ATTR_SEARCH;
					}
				}
			}
		}

#		$r = $self->{_rules}->{$tag}->{$attr} if ref $self->{_rules}->{$tag};
#		$r = $self->{_rules}->{$tag}->{"*"}   if !defined($r) && ref $self->{_rules}->{$tag};
#		$r = $self->{_rules}->{"_"}->{$attr}  if !defined($r) && ref $self->{_rules}->{"_"};
#		$r = $self->{_rules}->{"_"}->{"*"}    if !defined($r) && ref $self->{_rules}->{"_"};
#		$r = $self->{_rules}->{"*"}->{$attr}  if !defined($r) && ref $self->{_rules}->{"*"};
#		$r = $self->{_rules}->{"*"}->{"*"}    if !defined($r) && ref $self->{_rules}->{"*"};

		if (ref($r) eq 'Regexp') {
			$child->attr($attr, undef) unless $child->attr($attr) =~ /$r/;
		} 

		elsif (ref($r) eq 'CODE') {
			debug "        code ref, attr $attr=" . $child->attr($attr) . "\n";
			local $_ = $child->attr($attr);
			if ($r->($child, $attr, $child->attr($attr))) {
				if ($_ ne $child->attr($attr)) {
					$child->attr($attr, $_);
				}
			} else {
				$child->attr($attr, undef);
			}
		} 

		elsif (!$r) {
			debug "    Stripping attribute\n";
			$child->attr($attr, undef);
		}
	}
}

1;
__END__

=head1 NAME

HTML::Sanitizer - HTML Sanitizer

=head1 SYNOPSIS

  my $safe = new HTML::Sanitizer;

  $safe->permit_only(
	qw/ strong em /,
	a => {
		href => qr/^(?:http|ftp):/,
		title => 1,
	},
	img => {
		src => qr/^(?:http|ftp):/,
		alt => 1,
	},
        b => HTML::Element->new('strong'),
  );

  $sanitized = $safe->filter_html_fragment($evil_html);

  # or

  my $tree = HTML::TreeBuilder->new->parse_file($filename);
  $safe->sanitize_tree($tree);

=head1 ABSTRACT

This module acts as a filter for HTML.  It is not a validator, though it
might be possible to write a validator-like tool with it.  It's intended
to strip out unwanted HTML elements and attributes and leave you with
non-dangerous HTML code that you should be able to trust.

=head1 DESCRIPTION

First, though this module attempts to strip out unwanted HTML, I
make no guarantee that it will be unbeatable.  Tread lightly when
using untrusted data.  Also take note of the low version number.

=head2 RULE SETUP

See the L<RULE SETS> section below for details on what a rule set
actually is.  This section documents the methods you'd use to
set one up.

=over 4

=item new(...)

Creates a new C<HTML::Sanitizer> object, using the given ruleset.
Alternatively, a ruleset can be built piecemeal using the permit/deny
methods described below.

See the section on L<RULE SETS> below to see how to construct a
filter rule set.  An example might be:

  $safe = new HTML::Sanitizer(
     strong => 1,			# allow <strong>, <em> and <p>
     em => 1,
     p => 1,
     a => { href => qr/^http:/ },	# allow HTTP links
     b => HTML::Element->new('strong'), # convert <b> to <strong>
     '*' => 0,				# disallow everything else
  );

=item permit(...)

Accepts a list of rules and assumes each rule will have a true
value.  This allows you to be a little less verbose, since your
rule sets can look like this instead of a large data structure:

  $safe->permit( qw/ strong em i b br / );

Though you're still free to include attributes and more complex
validation requirements, if you still need them:

  $safe->permit( img => [ qw/ src alt / ], ... );

  $safe->permit( a => { href => qr/^http:/ }, 
                 blockquote => [ qw/ cite id / ], 
                 b => HTML::Element->new('strong'),
                 qw/ strong em /);

The value to each element should be an array, hash or code reference,
or an HTML::Element object, since the '=> 1' is always implied otherwise.

=item permit_only(...)

Like permit, but also assumes a default 'deny' policy.  This is
equivalent to including this in your ruleset as passed to new():

  '*' => undef

This will destroy any existing rule set in favor of the one you pass it.

If you would rather use a default 'ignore' policy, you could do
something like this:

  $safe->permit_only(...);
  $safe->ignore('*');

=item deny(...)

Like permit, but assumes each case will have a 'false' value by assuming a
'=> undef' for each element that isn't followed by an array reference.
This will cause any elements matching these rules to be stripped from
the document tree (along with any child elements).  You cannot pass
a hash reference of attributes, a code reference or an HTML::Element
object as a value to an element, as in permit.  If you need more complex
validation requirements, follow up with a permit() call or define them
in your call to new().

  $safe->deny( a => ['href'], qw/ img object embed script style /);

=item deny_only(...)

Like deny, but assumes a default 'permit' policy.  This is equivalent
to including this in your ruleset:

  '*' => { '*' => 1 }	# allow all elements and all attributes

This will destroy any existing rule set in favor of the one you pass it.

=item ignore(...)

Very similar to deny, this will cause a rule with an implied '=> 0' to
be created for the elements passed.  Matching elements will be replaced
with their child elements, with the element itself being removed from
the document tree.

=item ignore_only(...)

Like ignore, but assumes a default 'permit' policy.  See 'deny_only'.

=back

=head2 FILTER METHODS

=over 4

=item sanitize_tree($tree)

This runs the filter on a parse tree, as generated by HTML::TreeParser.
This WILL modify $tree.  This function is used by the filter functions
below, so you don't have to deal with HTML::TreeParser unless you
want to.

=item filter_html($html)

Filters an HTML document using the configured rule set.

=item filter_html_fragment($html)

Filters an HTML fragment.  Use this if you're filtering a chunk of
HTML that you're going to end up using within an existing document.
(In other words, it operates on $html as if it were a complete document,
but only ends up working on children of the <body> tag.)

=item filter_xml($xml)

=item filter_xml_fragment($xml)

Like above, but operates on the data as though it were well-formed XML.
Use this if you intend on providing XHTML, for example.

=back

When the above functions encounter an attribute they're meant to filter,
the attribute will be deleted from the element, but the element will
survive.  If you need to delete the entire element if an attribute
doesn't pass validation, set up a coderef for the element in your rule
set and use L<HTML::Element> methods to manipulate the element (e.g. by
calling C<$element->delete> or C<$element->replace_with_content> if
C<$element->attr('href')> doesn't pass muster.)

=head1 RULE SETS

A rule set is simply a list of elements and/or attributes and values
indicating whether those elements/attributes will be allowed, ignored,
or stripped from the parse tree.  Generally rule sets should be passed
to new() at object creation time, though they can also be built piecemeal
through calls to permit, deny and/or ignore as described above.

Each element in the list should be followed by one of the following:

=over 4

=item a 'true' value

This indicates the element should be permitted as-is with no filtering
or modification (aside from any other filtering done to child elements).

=item 0

If a zero (or some other defined, false value) is given, the element
itself is deleted but child elements are brought up to replace it.
Use this when you wish to filter a bad formatting tag while preserving
the text it was formatting, for example.

=item undef

If an undef is given, the element and all of its children will be deleted.
This would remove a scripting tag and all of its contents from the
document tree, for example.

=item an HTML::Element object

A copy of this object will replace the element matching the rule.
The attributes in the replacement object will overlay the attributes of
the original object (after attribute filtering has been done through
the _ rule).  If this element contains any child elements, they will
replace the children of the element fitting the rule.  If you wish
to delete the content without necessarily providing any replacement,
create a child that's simply an empty text node.

=item a code reference

This would permit the element if, and only if, the coderef returned a
true value.  The HTML::Element object in question is passed as the first
and only argument.

=item a hash reference

This implies the element itself is OK, but that some additional checking
of its attribute list is needed.  This hash reference should contain
keys of attributes and values that in turn should be one of:

=over 4

=item a 'true' value

This would preserve the attribute.

=item a 'false' value

This would delete the attribute.

=item a regular expression

This would preserve the attribute if the regular expression matched.

=item a code reference

This would permit the attribute if and only if the coderef returned
a true value.  The HTML::Element object, the attribute name and
attribute value are passed as arguments.  $_ is also set to the
attribute value (which can be modified).

=back 4

=back 4

=head2 EXAMPLES

Here is a sample rule set, which might do a fair job at stripping out
potentially dangerous tags, though I put this together without too much
thought, so I wouldn't rely on it:

  'script'          => undef,
  'style'           => undef,
  '*'               => {
  	onclick     => 0,
  	ondblclick  => 0,
  	onselect    => 0,
  	onmousedown => 0,
  	onmouseup   => 0,
  	onmouseover => 0,
  	onmousemove => 0,
  	onmouseout  => 0,
  	onfocus     => 0,
  	onblur      => 0,
  	onkeypress  => 0,
  	onkeydown   => 0,
  	onkeyup     => 0,
  	onselect    => 0,
  	onload      => 0,
  	onunload    => 0,
  	onerror     => 0,
  	onsubmit    => 0,
  	onreset     => 0,
  	onchange    => 0,
  	style       => 0,
  	href        => qr/^(?!(?:java)?script)/,
  	src         => qr/^(?!(?:java)?script)/,
  	cite        => sub { !/^(?:java)?script/ },  # same thing, mostly
  	'*'         => 1,
  },
  'link'            => {
  	rel         => sub { not_member("stylesheet", @_) },
  },
  'object'          => 0,	# strip but let children show through
  'embed'           => undef,
  'iframe'          => undef,
  'frameset'        => undef,
  'frame'           => undef,
  'applet'          => undef,
  'noframes'        => 0,
  'noscript'        => 0,

  # use a function like this to do some additional validation:

  sub not_member { !/\b\Q$_[0]\E\b/i; }	# maybe substitute it out instead

A web site incorporating user posts might want something a little more
strict:

  em           => 1,
  strong       => 1,
  p            => 1,
  ol           => 1,
  ul           => 1,
  li           => 1,
  tt           => 1,
  a            => 1,
  img          => 1,
  span         => 1,
  blockquote   => { cite => 1 },
  _            => {	 # for all tags above, these attribute rules apply:
      href     => qr/^(?:http|ftp|mailto|sip):/i,
      src      => qr/^(?:http|ftp|data):/i,
      title    => 1,
                  # Maybe add an x- prefix to all ID's to avoid collisions
      id       => sub { $_ = "x-$_" },
      xml:lang => 1,
      lang     => 1,
      *        => 0,
  },
  '*'          => 0,	 # everything else is 'ignored'
  script       => undef, # except these, which are stripped along with children
  style        => undef,

Note the use of the _ element here, which is magic in that it allows you
to set up some global attributes while still leaving the * element free
to express a default 'deny' policy.  The attributes specified here will
be applied to all of the explicitly defined elements (em, strong, etc.),
but they will not be applied to elements not present in the ruleset.

Attribute rule precedence goes from the tag-specific, the special "_" tag
and then the special "*" tag.

The following might be a simple way to force a 'b' tag to become a
'strong' tag, with the text within it surviving:

  b => HTML::Element->new('strong');

Here's how you might strip out a 'script' tag while letting the user
know something is up:

  script => HTML::Element
	->new('p', class => 'script_warning')
	->push_content("Warning: A <script> tag was removed!");

=head1 OTHER CONSIDERATIONS

This module just deals with HTML tags.	There are other ways of injecting
potentially harmful code into documents, including CSS, faking out
an img or object tag, etc.  Without extending this module to include
a CSS parser, for example, addressing these cases will be difficult.
It's recommended that tags and attributes like this simply be stripped.

If you're using this to sanitize code provided by a 3rd party, also check
to ensure that you're either matching character sets, or converting as
necessary.

=head1 BUGS

=over 4

=item This release has no known bugs, but prior releases may have contained
bugs that were fixed with this release.  See http://rt.cpan.org/ for details.

=back

=head1 SEE ALSO

L<HTML::TreeBuilder>, L<HTML::Element>, L<HTML::Parser>, L<Safe>

=head1 AUTHOR

Copyright (c) 2003 David Nesting.  All Rights Reserved.

This library is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

This program is distributed in the hope that it will be useful, but
without any warranty; without even the implied warranty of merchantability
or fitness for a particular purpose.


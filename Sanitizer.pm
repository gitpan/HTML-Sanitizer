package HTML::Sanitizer;

use HTML::TreeBuilder;
use strict;
use warnings;
use Carp;

our $VERSION = 0.01;

use constant DEBUG => 0;

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

		if (ref $attrs) {
			$attrs = array2hash($attrs);
			foreach (keys %{$attrs}) {
				$self->{_rules}->{$element}->{$_} = $attrs->{$_};
			}
		} elsif (defined $attrs) {
			unshift(@_, $attrs);
		}
	}
}

sub deny {
	my $self = shift;

	while (@_) {
		my $element = shift;
		my $attrs = shift;

		if (ref $attrs) {
			foreach (@{$attrs}) {
				$self->{_rules}->{$element}->{$_} = 0;
			}
			next;
		} elsif (defined $attrs) {
			unshift(@_, $attrs);
		}

		$self->{_rules}->{$element} = 0;
	}
}

sub permit_only {
	my $self = shift;

	$self->{_rules}->{'*'} = 0;
	$self->permit(@_);
}

sub deny_only {
	my $self = shift;

	$self->{_rules}->{'*'}->{'*'} = 1;
	$self->deny(@_);
}

sub filter_as_xml {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	return $tree->as_XML;
}

sub filter_as_xml_fragment {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	my $body = $tree->find_by_tag_name('body');
	$body ||= $tree;
	return join("", map { ref() ? $_->as_XML : $_ } $body->content_list);
}

sub filter_as_html {
	my $self = (@_);
	my $tree = &_filter;
	return unless $tree;

	return $tree->as_HTML;
}

sub filter_as_html_fragment {
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

	foreach my $child ($tree->content_list) {
		if (ref($child)) {
			my $tag = lc $child->tag;
			debug "Examining tag $tag\n";

			if ($rules->{$tag}) {
				debug "  Tag has a rule\n";

				$self->sanitize_attributes($child);
				if (ref($rules->{$tag}) eq 'CODE') {
					unless ($rules->{$tag}->($child)) {
						next if $self->_filter_child($child);
					}
				}

			} elsif ($rules->{'*'}) {
				debug "  Tag has no rule, but there's a default rule\n";

				$self->sanitize_attributes($child);
				if (ref($rules->{'*'}) eq 'CODE') {
					unless ($rules->{'*'}->($child)) {
						next if $self->_filter_child($child);
					}
				}

			} else {
				debug "  No rule found, defaulting to deny\n";
				next if $self->_filter_child($child);
			}

			debug "  $tag is ok\n";	
				
			$self->sanitize_tree($child) if $child;
		}
	}
}

sub _filter_child {
	my ($self, $child) = @_;

	debug "  filtering tag " . $child->tag . "\n";
	if ($self->{preserve_children}) {
		$child->replace_with_content->delete;
		return 0;
	} else {
		$child->delete;
		return 1;
	}
}

sub sanitize_attributes {
	my ($self, $child) = @_;
	my $tag = lc $child->tag;

	foreach my $attr ($child->all_external_attr_names) {
		$attr = lc $attr;
		debug "    Checking attribute <$tag $attr>\n";

		my $r;
		$r = $self->{_rules}->{$tag}->{$attr} if ref $self->{_rules}->{$tag};
		$r = $self->{_rules}->{$tag}->{"*"}  if !defined($r) && ref $self->{_rules}->{$tag};
		$r = $self->{_rules}->{"_"}->{$attr} if !defined($r) && ref $self->{_rules}->{"_"};
		$r = $self->{_rules}->{"_"}->{"*"}   if !defined($r) && ref $self->{_rules}->{"_"};
		$r = $self->{_rules}->{"*"}->{$attr} if !defined($r) && ref $self->{_rules}->{"*"};
		$r = $self->{_rules}->{"*"}->{"*"}   if !defined($r) && ref $self->{_rules}->{"*"};

		if (ref($r) eq 'Regexp') {
			$child->attr($attr, undef) unless $child->attr($attr) =~ /$r/;
		} elsif (ref($r) eq 'CODE') {
			debug "        code ref, attr $attr=" . $child->attr($attr) . "\n";
			$child->attr($attr, undef) unless $r->($child, $attr, $child->attr($attr));
		} elsif (!$r) {
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
		href => qr/^http:|ftp:/,
		title => 1,
	},
	img => {
		src => qr/^http:|ftp:/,
		alt => 1,
	},
  );

  $sanitized = $safe->filter_as_html_fragment($evil_html);

  # or

  my $tree = HTML::TreeBuilder->new->parse_file($filename);
  $safe->sanitize_tree($tree);

=head1 ABSTRACT

This module acts as a filter for HTML text.  It is not a validator,
though it might be possible to write a validator-like tool with it.
It's intended to strip out unwanted HTML elements and attributes and
leave you with non-dangerous HTML code that you should be able to trust.

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
filter rule set.

=item permit(...)

Accepts a list of rulesets and assumes each rule will have a true
value.  This allows you to be a little less verbose, since your
rule sets can look like this instead:

  $safe->permit( qw/ strong em i b br / );

Though you're still free to include attributes and more complex
validation requirements, if you still need them:

  $safe->permit( img => [ qw/ src alt / ], ... );

  $safe->permit( a => { href => qr/^http:/ }, 
                 blockquote => [ qw/ cite id / ], 
                 qw/ strong em /);

=item permit_only(...)

Like permit, but also assumes a default 'deny' policy.  This is
equivalent to including this in your ruleset:

  '*' => 0

=item deny(...)

Like permit, but fills in the gaps with false values.

  $safe->deny( a => ['href'], qw/ img object embed script style /);

=item deny_only(...)

Like deny, but assumes a default 'permit' policy.  This is equivalent
to including this in your ruleset:

  '*' => { '*' => 1 }	# allow all elements and all attributes

=back

=head2 FILTER METHODS

=over 4

=item sanitize_tree($tree)

This runs the filter on a parse tree, as generated by HTML::TreeParser.
This WILL modify $tree.  This function is used by the filter functions
below, so you don't have to deal with HTML::TreeParser unless you
want to.

=item filter_as_html($html)

Filters an HTML document using the configured rule set.

=item filter_as_html_fragment($html)

Filters an HTML fragment.  Use this if you're filtering a chunk of
HTML that you're going to end up using within an existing document.
(In other words, it operates on $html as if it were a complete document,
but only ends up working on children of the <body> tag.)

=item filter_as_xml($xml)

=item filter_as_xml_fragment($xml)

Like above, but operates on the data as though it were well-formed XML.
Use this if you intend on providing XHTML, for example.

=back

When the above functions encounter an element they're meant to filter,
the entire element will be deleted, including children.  If you wish
to preserve child elements, you can try setting this experimental flag,
but at the moment I make no promises that child nodes will be filtered:

  $safe->{preserve_children} = 1;

=head1 RULE SETS

A rule set is simply a list of elements and/or attributes and values
indicating whether those elements/attributes will be allowed,
ignored, or stripped from the parse tree.

Each element in the list can be followed either by a true/false value
(true being equivalent to a 'permit' rule for the element, while a
false value means 'deny'), a hashref with additional attribute rules,
or a code reference (@_ = ($element)).

If an element is followed by a hashref, the keys of the hashref will
be attributes we wish to inspect.  The values of the hashref can either
be true/false as above (to permit or strip the attribute), a regular
expression (which must be true to allow the attribute to survive), or
a code reference (@_ = ($element, $attr_name, $attr_value)).

Here is a sample rule set, which might do a fair job at stripping out
potentially dangerous tags, though I put this together without too much
thought, so I wouldn't rely on it:

  'script'          => 0,
  'style'           => 0,
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
  	cite        => qr/^(?!(?:java)?script)/,
  	'*'         => 1,
  },
  'link'            => {
  	rel         => sub { not_member("stylesheet", @_) },
  },
  'object'          => 0,
  'embed'           => 0,
  'iframe'          => 0,
  'frameset'        => 0,
  'frame'           => 0,
  'applet'          => 0

  # use a function like this to do some additional validation:

  sub not_member {
	my ($what, $element, $attribute, $value) = @_;
	return $value !~ /\b$what\b/i;
  }

  # or maybe:

  sub not_member {
        my ($what, $element, $attribute, $value) = @_;
        if ($value =~ s/\b$what\b//i) {
            $element->attr($attribute, $value);
        }
        return 1;
  }

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
  _            => {
      href     => qr/^(?:http|ftp|mailto|sip):/i,
      src      => qr/^(?:http|ftp|data):/i,
      title    => 1,
                  # Maybe add an x- prefix to all ID's to avoid collisions
      id       => sub { $_[2] = "x-$_[2]"; $_[0]->attr($_[1], $_[2]); 1 },
      xml:lang => 1,
      lang     => 1,
      *        => 0,
  },
  '*'          => 0

Note the use of the _ element here, which is magic in that it allows you
to set up some global attributes while still leaving the * element free
to express a default 'deny' policy.  The attributes specified here will
be applied to all of the explicitly defined elements (em, strong, etc.),
but they will not be applied to elements not present in the ruleset.

Attribute rule precedence goes from the tag-specific, the special "_" tag
and then the special "*" tag.

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

=item The "preserve_children" flag may not allow for the filtering of
"preserved" child elements, since we're changing the content_list of
the parent element after we've started iterating over it.

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


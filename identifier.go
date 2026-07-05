package spec

import "regexp"

// identifierRe constrains declared threat model ids to dot-separated
// lowercase identifier-safe segments: each segment usable as an HCL traversal
// part, no leading digit, no dashes (which are ambiguous with subtraction in
// HCL expressions). A dotted id places the model in a namespace hierarchy, so
// tooling can offer references like threatmodel.apps.tower alongside flat
// ones like threatmodel.tower_of_london.
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// ValidIdentifier reports whether s is acceptable as a declared threat model
// id.
func ValidIdentifier(s string) bool {
	return identifierRe.MatchString(s)
}

// IdentifierPrefixes returns the proper namespace prefixes of a dotted id:
// "apps.web.tower" → ["apps", "apps.web"]. A flat id has none. An id may not
// equal another id's namespace prefix — the reference tree can't hold a model
// and a namespace at the same address — which the parser enforces for
// declared ids.
func IdentifierPrefixes(id string) []string {
	out := []string{}
	for i, r := range id {
		if r == '.' {
			out = append(out, id[:i])
		}
	}
	return out
}

// DeriveIdentifier converts a display name to identifier form:
// "Tower of London" → "tower_of_london". It shares its derivation with the
// OTM exporter's ids (which use dashes instead of underscores). The result is
// not guaranteed to satisfy ValidIdentifier — a name like "3rd Party Gateway"
// derives to a digit-leading token — so consumers offering dotted references
// should check.
func DeriveIdentifier(name string) string {
	return toKebabUnder(name)
}

// Identifier returns the threat model's addressable identity: the declared
// id when present, otherwise one derived from the name. Only declared ids
// are validated and rename-stable; derived ones shift with the name.
func (tm *Threatmodel) Identifier() string {
	if tm.Id != "" {
		return tm.Id
	}
	return DeriveIdentifier(tm.Name)
}

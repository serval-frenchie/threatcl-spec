package spec

import "regexp"

// identifierRe constrains declared threat model ids to lowercase
// identifier-safe tokens: usable as an HCL traversal part (so tooling can
// offer dotted references like threatmodel.tower_of_london), no leading
// digit, no dashes (which are ambiguous with subtraction in HCL
// expressions).
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// ValidIdentifier reports whether s is acceptable as a declared threat model
// id.
func ValidIdentifier(s string) bool {
	return identifierRe.MatchString(s)
}

// DeriveIdentifier converts a display name to identifier form:
// "Tower of London" → "tower_of_london". It is SlugifyUnderscore, which
// shares its derivation with the OTM exporter's ids (those use dashes
// instead of underscores). The result is not guaranteed to satisfy
// ValidIdentifier — a name like "3rd Party Gateway" derives to a
// digit-leading token — so consumers offering dotted references should check.
func DeriveIdentifier(name string) string {
	return SlugifyUnderscore(name)
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

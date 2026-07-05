package spec

import (
	"fmt"
	"regexp"

	"github.com/hashicorp/go-multierror"
)

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

// ValidateUniqueIdentifiers checks a set of threat models for identifier
// collisions. Parse-time validation only ever sees one file's models, so
// consumers that aggregate models across files (e.g. to build a reference
// registry keyed by Identifier()) should run their combined set through this
// before relying on identifiers as addresses.
//
// Every declared id must be identifier-safe, and no two models may share an
// effective Identifier() — declared or derived — since a registry needs one
// address per model. Derived identifiers are only collision-checked, never
// format-checked: a derivation like "3rd Party Gateway" → "3rd_party_gateway"
// isn't addressable in dotted form but is still a legal registry key.
func ValidateUniqueIdentifiers(tms []Threatmodel) error {
	var errMap error
	seen := map[string]string{} // identifier → name of the model that claimed it

	for i := range tms {
		tm := &tms[i]

		if tm.Id != "" && !ValidIdentifier(tm.Id) {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': invalid id '%s' - must be lowercase letters, digits or underscores, starting with a letter",
				tm.Name,
				tm.Id,
			))
		}

		ident := tm.Identifier()
		if ident == "" {
			continue
		}

		if otherName, ok := seen[ident]; ok {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': identifier '%s' collides with TM '%s'",
				tm.Name,
				ident,
				otherName,
			))
			continue
		}
		seen[ident] = tm.Name
	}

	return errMap
}

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

// reservedIdSegments are the attribute names a threat model object exposes
// (HCL schema names plus the plural forms reference-building tooling uses).
// A child id's segment directly beneath a parent model's id can't be one of
// these: in a reference tree the parent's children sit alongside its fields,
// so "buildings.threats" would shadow the threats of the model with id
// "buildings".
var reservedIdSegments = map[string]bool{
	"name": true, "id": true, "extends": true, "description": true,
	"imports": true, "including": true, "link": true, "diagram_link": true,
	"repository": true, "author": true, "created_at": true, "updated_at": true,
	"attributes": true, "additional_attribute": true, "additional_attributes": true,
	"information_asset": true, "information_assets": true,
	"threat": true, "threats": true,
	"usecase": true, "usecases": true,
	"exclusion": true, "exclusions": true,
	"third_party_dependency": true, "third_party_dependencies": true,
	"data_flow_diagram": true, "data_flow_diagram_v2": true, "data_flow_diagrams": true,
	"mermaid": true, "mermaid_diagrams": true,
	"controls": true, "proposed_controls": true,
}

// ReservedIdSegment reports whether s can't be used as an id segment directly
// beneath a parent model's id.
func ReservedIdSegment(s string) bool {
	return reservedIdSegments[s]
}

// IdentifierPrefixes returns the proper namespace prefixes of a dotted id:
// "apps.web.tower" → ["apps", "apps.web"]. A flat id has none. When a prefix
// is itself another model's declared id, that model is the namespace's
// parent: it lives at the prefix address and its children sit beneath it
// (subject to ReservedIdSegment).
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

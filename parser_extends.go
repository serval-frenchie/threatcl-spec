package spec

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-multierror"
)

// resolveExtends applies `extends` inheritance across the parsed set. A model
// naming another model's declared id inherits its collections and attributes
// (see inheritFrom). Chains resolve parent-first, so a grandchild sees
// content inherited through the middle of the chain; cycles and unknown
// targets are errors. Runs after per-model validation, so inherited content
// has already been normalized on the parent.
func (p *ThreatmodelParser) resolveExtends() error {
	var errMap error

	byId := make(map[string]*Threatmodel)
	for i := range p.wrapped.Threatmodels {
		t := &p.wrapped.Threatmodels[i]
		if t.Id != "" {
			byId[t.Id] = t
		}
	}

	const (
		unresolved = iota
		resolving
		resolved
	)
	state := make(map[*Threatmodel]int)

	var resolve func(t *Threatmodel, chain []string) error
	resolve = func(t *Threatmodel, chain []string) error {
		if t.Extends == "" || state[t] == resolved {
			return nil
		}
		if state[t] == resolving {
			return fmt.Errorf(
				"TM '%s': extends cycle: %s",
				t.Name,
				strings.Join(append(chain, t.Identifier()), " -> "),
			)
		}
		state[t] = resolving
		defer func() { state[t] = resolved }()

		parent, ok := byId[t.Extends]
		if !ok {
			return fmt.Errorf(
				"TM '%s': extends references unknown threat model id '%s'",
				t.Name,
				t.Extends,
			)
		}
		if err := resolve(parent, append(chain, t.Identifier())); err != nil {
			return err
		}
		t.inheritFrom(parent)
		return nil
	}

	for i := range p.wrapped.Threatmodels {
		if err := resolve(&p.wrapped.Threatmodels[i], nil); err != nil {
			errMap = multierror.Append(errMap, err)
		}
	}

	return errMap
}

// inheritFrom merges the parent's collections into tm — same-named items
// already on tm win — and adopts the parent's attributes block when tm
// declares none. Deliberately narrower than Include(): scalars (description,
// link, ...), data flow diagrams and mermaid diagrams stay per-model.
func (tm *Threatmodel) inheritFrom(parent *Threatmodel) {
	if tm.Attributes == nil && parent.Attributes != nil {
		attrs := *parent.Attributes
		tm.Attributes = &attrs
	}

	for _, ia := range parent.InformationAssets {
		tm.addInfoIfNotExist(*ia)
	}

	for _, uc := range parent.UseCases {
		tm.addUcIfNotExist(*uc)
	}

	for _, ex := range parent.Exclusions {
		tm.addExclIfNotExist(*ex)
	}

	for _, tpd := range parent.ThirdPartyDependencies {
		tm.addTpdIfNotExist(*tpd)
	}

	for _, t := range parent.Threats {
		tm.addTIfNotExist(*t)
	}
}

package spec

import (
	"sort"

	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// resolveRef resolves a reference against candidate element names. An exact
// name match always wins; otherwise the reference matches candidates whose
// slug equals the reference's slug, so authors can refer to "Web App" as
// "web_app" or "web-app" (or via dot notation, which evaluates to the
// underscore slug). Comparison is done on the underscore form, which makes
// the kebab (OTM id) and underscore (dot notation) spellings equivalent.
// Returns the canonical name when the reference resolves to exactly one
// candidate, or the (sorted) candidate names when the slug is ambiguous. Both
// return values are zero when nothing matches.
func resolveRef(ref string, candidates []string) (canonical string, ambiguous []string) {
	for _, c := range candidates {
		if ref == c {
			return c, nil
		}
	}

	slug := SlugifyUnderscore(ref)
	if slug == "" {
		return "", nil
	}

	matches := []string{}
	for _, c := range candidates {
		if SlugifyUnderscore(c) == slug {
			matches = append(matches, c)
		}
	}

	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return matches[0], nil
	default:
		sort.Strings(matches)
		return "", matches
	}
}

// slugMatchesName reports whether ref refers to name via slug equality,
// comparing on the underscore form so both divider spellings match.
func slugMatchesName(ref, name string) bool {
	slug := SlugifyUnderscore(ref)
	return slug != "" && slug == SlugifyUnderscore(name)
}

// extractRefSlugs does a shallow parse of an HCL file collecting the labels of
// referenceable elements (information assets, DFD processes, external
// elements, data stores, and trust zones) as identifier-safe underscore slugs,
// grouped by block type. buildRefCtx turns these into evaluation-context
// namespaces so references can be written with dot notation
// (from = process.web_app) instead of quoted strings. Underscore slugs keep
// dotted references consistent with the threatmodel id convention and avoid
// the hyphen/subtraction ambiguity in bare HCL expressions. Each slug
// evaluates to itself; slug-to-name resolution happens later, per threat
// model, during validation.
func extractRefSlugs(f *hcl.File) map[string]map[string]cty.Value {
	out := map[string]map[string]cty.Value{
		"information_asset": {},
		"process":           {},
		"external_element":  {},
		"data_store":        {},
		"trust_zone":        {},
	}

	addSlug := func(kind string, labels []string) {
		if len(labels) == 0 {
			return
		}
		if slug := SlugifyUnderscore(labels[0]); slug != "" {
			out[kind][slug] = cty.StringVal(slug)
		}
	}

	elementSchema := &hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "process", LabelNames: []string{"name"}},
			{Type: "external_element", LabelNames: []string{"name"}},
			{Type: "data_store", LabelNames: []string{"name"}},
			{Type: "trust_zone", LabelNames: []string{"name"}},
		},
	}

	tms, _, _ := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "threatmodel", LabelNames: []string{"name"}},
		},
	})

	for _, tmBlock := range tms.Blocks {
		tmContent, _, _ := tmBlock.Body.PartialContent(&hcl.BodySchema{
			Blocks: []hcl.BlockHeaderSchema{
				{Type: "information_asset", LabelNames: []string{"name"}},
				{Type: "data_flow_diagram_v2", LabelNames: []string{"name"}},
				{Type: "data_flow_diagram"},
			},
		})

		for _, blk := range tmContent.Blocks {
			if blk.Type == "information_asset" {
				addSlug("information_asset", blk.Labels)
				continue
			}

			// Both DFD variants share the same element blocks.
			dfdContent, _, _ := blk.Body.PartialContent(elementSchema)
			for _, el := range dfdContent.Blocks {
				addSlug(el.Type, el.Labels)
				if el.Type != "trust_zone" {
					continue
				}
				zoneContent, _, _ := el.Body.PartialContent(elementSchema)
				for _, zel := range zoneContent.Blocks {
					if zel.Type != "trust_zone" {
						addSlug(zel.Type, zel.Labels)
					}
				}
			}
		}
	}

	return out
}

// buildRefCtx populates the evaluation context with one namespace per element
// block type, each mapping an element's slug to that slug as a string. A
// namespace is only set when at least one element of that type exists, so an
// unknown root still reads as "There is no variable named ...".
func (p *ThreatmodelParser) buildRefCtx(ctx *hcl.EvalContext, refSlugs map[string]map[string]cty.Value) {
	for kind, slugs := range refSlugs {
		if len(slugs) == 0 {
			continue
		}
		ctx.Variables[kind] = cty.ObjectVal(slugs)
	}
}

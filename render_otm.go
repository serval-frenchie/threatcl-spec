package spec

import (
	"fmt"

	"github.com/threatcl/go-otm/pkg/otm"
)

func (tm *Threatmodel) RenderOtm() (otm.OtmSchemaJson, error) {
	o := otm.OtmSchemaJson{}
	o.OtmVersion = OtmVersion

	o.Project.Name = tm.Name
	o.Project.Id = Slugify(tm.Name)
	o.Project.Description = pToStr(tm.Description)
	o.Project.Owner = pToStr(tm.Author)
	o.Project.Attributes = tm.getAttributes()

	for _, ia := range tm.InformationAssets {
		asset := otm.OtmSchemaJsonAssetsElem{
			Name:        ia.Name,
			Id:          Slugify(ia.Name),
			Description: pToStr(ia.Description),
		}

		attr := make(map[string]interface{})
		if ia.InformationClassification != "" {
			attr["information_classification"] = ia.InformationClassification
		}

		if ia.Source != "" {
			attr["source"] = ia.Source
		}

		asset.Attributes = attr

		o.Assets = append(o.Assets, asset)
	}

	for idx, t := range tm.Threats {
		threatName := t.Name
		if threatName == "" {
			threatName = fmt.Sprintf("Threat %d", idx+1)
		}
		threat := otm.OtmSchemaJsonThreatsElem{
			Name:        threatName,
			Id:          Slugify(threatName),
			Description: pToStr(t.Description),
		}

		categories := make([]*string, 0)
		for _, stride := range t.Stride {
			categories = append(categories, pToStr(stride))
		}

		for _, impact := range t.ImpactType {
			categories = append(categories, pToStr(impact))
		}

		threat.Categories = categories

		// Map the optional risk block onto OTM's threat-level risk object
		// (likelihood/impact on a 0–100 scale, rationale into the comments) and
		// carry threatcl's computed severity/residual values as attributes,
		// since OTM has no native severity field.
		if t.Risk != nil {
			threat.Risk = otm.OtmSchemaJsonThreatsElemRisk{
				Likelihood: pFloat(float64(defaultRiskModel.OtmValues[t.Risk.Likelihood])),
				Impact:     float64(defaultRiskModel.OtmValues[t.Risk.Impact]),
			}
			if t.Risk.Rationale != "" {
				threat.Risk.LikelihoodComment = pToStr(t.Risk.Rationale)
				threat.Risk.ImpactComment = pToStr(t.Risk.Rationale)
			}

			riskAttr := map[string]interface{}{
				"risk_severity":          t.Risk.Severity(),
				"risk_inherent_score":    t.Risk.InherentScore(),
				"risk_residual_score":    t.ResidualScore(),
				"risk_residual_severity": t.ResidualSeverity(),
			}
			threat.Attributes = riskAttr
		}

		o.Threats = append(o.Threats, threat)

		// We add mitigations while we're in here
		for _, control := range t.Controls {

			mitigation := otm.OtmSchemaJsonMitigationsElem{
				Name:          control.Name,
				Id:            Slugify(control.Name),
				Description:   pToStr(control.Description),
				RiskReduction: float64(control.RiskReduction),
			}

			attr := make(map[string]interface{})

			for _, atrVal := range control.Attributes {
				attr[SlugifyUnderscore(atrVal.Name)] = atrVal.Value
			}

			attr["implemented"] = control.Implemented

			if control.ImplementationNotes != "" {
				attr["implementation_notes"] = control.ImplementationNotes
			}

			mitigation.Attributes = attr

			o.Mitigations = append(o.Mitigations, mitigation)

		}
	}

	if tm.DiagramLink != "" {
		repr := otm.OtmSchemaJsonRepresentationsElem{
			Description: pToStr(tm.DiagramLink),
			Type:        "diagram",
			Name:        "Diagram 1",
			Id:          "diagram-1",
		}

		o.Representations = append(o.Representations, repr)
	}

	return o, nil
}

func (tm *Threatmodel) getAttributes() map[string]interface{} {
	attr := make(map[string]interface{})

	if tm.Attributes != nil {
		attr["new_initiative"] = tm.Attributes.NewInitiative
		attr["internet_facing"] = tm.Attributes.InternetFacing
		attr["initiative_size"] = tm.Attributes.InitiativeSize
	}

	if len(tm.Repository) > 0 {
		attr["repository"] = tm.Repository
	}

	for _, atrVal := range tm.AdditionalAttributes {
		attr[SlugifyUnderscore(atrVal.Name)] = atrVal.Value
	}

	return attr
}

func pToStr(s string) *string {
	return &s
}

func pFloat(f float64) *float64 {
	return &f
}

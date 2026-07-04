package spec

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

type ThreatmodelSpecConfig struct {
	Version                        string
	InitiativeSizes                []string `hcl:"initiative_sizes,optional"`
	DefaultInitiativeSize          string   `hcl:"default_initiative_size,optional"`
	InfoClassifications            []string `hcl:"info_classifications,optional"`
	DefaultInfoClassification      string   `hcl:"default_info_classification,optional"`
	ImpactTypes                    []string `hcl:"impact_types,optional"`
	STRIDE                         []string `hcl:"strides,optional"`
	UptimeDepClassifications       []string `hcl:"uptime_dep_classifications,optional"`
	DefaultUptimeDepClassification string   `hcl:"default_uptime_dep_classification,optional"`

	// AllowRemoteImports gates whether a threat model's `imports` /
	// `including` may reference remote sources (http, https, git, s3, gcs,
	// ...). It defaults to false: parsing an untrusted model must not be
	// able to trigger arbitrary network fetches (SSRF) or pull in remote
	// content. Operators who intentionally process trusted models that
	// reference remote sources opt in with `allow_remote_imports = true`.
	// Local file includes are always permitted (subject to path
	// containment) regardless of this flag.
	AllowRemoteImports bool `hcl:"allow_remote_imports,optional"`
}

func LoadSpecConfig() (*ThreatmodelSpecConfig, error) {
	specConfig := ThreatmodelSpecConfig{}
	specConfig.setDefaults()
	return &specConfig, nil
}

func (t *ThreatmodelSpecConfig) LoadSpecConfigFile(file string) error {

	specConfig := ThreatmodelSpecConfig{}

	info, err := os.Stat(file)
	if os.IsNotExist(err) {
		return fmt.Errorf("config error: No file found")
	}

	if !info.IsDir() {
		// config file appears to exist, let's try and open it
		parser := hclparse.NewParser()
		f, diags := parser.ParseHCLFile(file)

		if diags.HasErrors() {
			return diags
		}

		diags = gohcl.DecodeBody(f.Body, nil, &specConfig)

		if diags.HasErrors() {
			return diags
		}

		if len(specConfig.InitiativeSizes) > 0 {
			t.InitiativeSizes = specConfig.InitiativeSizes
		}
		if specConfig.DefaultInitiativeSize != "" {
			t.DefaultInitiativeSize = specConfig.DefaultInitiativeSize
		}
		if len(specConfig.InfoClassifications) > 0 {
			t.InfoClassifications = specConfig.InfoClassifications
		}
		if specConfig.DefaultInfoClassification != "" {
			t.DefaultInfoClassification = specConfig.DefaultInfoClassification
		}
		if len(specConfig.ImpactTypes) > 0 {
			t.ImpactTypes = specConfig.ImpactTypes
		}
		if len(specConfig.STRIDE) > 0 {
			t.STRIDE = specConfig.STRIDE
		}
		if len(specConfig.UptimeDepClassifications) > 0 {
			t.UptimeDepClassifications = specConfig.UptimeDepClassifications
		}
		if specConfig.DefaultUptimeDepClassification != "" {
			t.DefaultUptimeDepClassification = specConfig.DefaultUptimeDepClassification
		}

		// AllowRemoteImports is a security-relevant toggle, so honour the
		// value from the config file directly (default false when absent).
		t.AllowRemoteImports = specConfig.AllowRemoteImports

		return nil
	}

	// we got passed a dir
	return fmt.Errorf("config error: We can't process directories")

}

func (t *ThreatmodelSpecConfig) setDefaults() {
	t.Version = Version
	t.InitiativeSizes = append(t.InitiativeSizes, "Undefined")
	t.InitiativeSizes = append(t.InitiativeSizes, "Small")
	t.InitiativeSizes = append(t.InitiativeSizes, "Medium")
	t.InitiativeSizes = append(t.InitiativeSizes, "Large")
	t.DefaultInitiativeSize = "Undefined"

	t.InfoClassifications = append(t.InfoClassifications, "Restricted")
	t.InfoClassifications = append(t.InfoClassifications, "Confidential")
	t.InfoClassifications = append(t.InfoClassifications, "Public")
	t.DefaultInfoClassification = "Confidential"

	t.ImpactTypes = append(t.ImpactTypes, "Confidentiality")
	t.ImpactTypes = append(t.ImpactTypes, "Integrity")
	t.ImpactTypes = append(t.ImpactTypes, "Availability")

	t.STRIDE = append(t.STRIDE, "Spoofing")
	t.STRIDE = append(t.STRIDE, "Tampering")
	t.STRIDE = append(t.STRIDE, "Repudiation")
	t.STRIDE = append(t.STRIDE, "Info Disclosure")
	t.STRIDE = append(t.STRIDE, "Denial Of Service")
	t.STRIDE = append(t.STRIDE, "Elevation Of Privilege")

	t.UptimeDepClassifications = append(t.UptimeDepClassifications, "none")
	t.UptimeDepClassifications = append(t.UptimeDepClassifications, "degraded")
	t.UptimeDepClassifications = append(t.UptimeDepClassifications, "hard")
	t.UptimeDepClassifications = append(t.UptimeDepClassifications, "operational")
	t.DefaultUptimeDepClassification = "none"
}

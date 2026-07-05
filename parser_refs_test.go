package spec

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
)

func TestResolveRef(t *testing.T) {
	candidates := []string{"Web App", "User Database", "web-app-legacy", "User DB"}

	cases := []struct {
		name         string
		ref          string
		expResolved  string
		expAmbiguous []string
	}{
		{"exact match", "Web App", "Web App", nil},
		{"kebab slug match", "web-app", "Web App", nil},
		{"underscore slug match", "web_app", "Web App", nil},
		{"slug match of slug-named element", "Web App Legacy", "web-app-legacy", nil},
		{"case and punctuation folded", "user database!", "User Database", nil},
		// The slug algorithm (OTM exporter precedent) inserts a divider
		// before every uppercase letter, so acronym runs split per letter.
		{"acronym kebab slug matches per-letter form", "user-d-b", "User DB", nil},
		{"acronym underscore slug matches per-letter form", "user_d_b", "User DB", nil},
		{"acronym slug does not match collapsed form", "user-db", "", nil},
		{"no match", "nope", "", nil},
		{"empty ref", "", "", nil},
		{"punctuation-only ref never slug-matches", "!!!", "", nil},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolved, ambiguous := resolveRef(tc.ref, candidates)
			if resolved != tc.expResolved {
				t.Errorf("resolveRef(%q) resolved to %q, want %q", tc.ref, resolved, tc.expResolved)
			}
			if len(ambiguous) != len(tc.expAmbiguous) {
				t.Errorf("resolveRef(%q) ambiguous = %v, want %v", tc.ref, ambiguous, tc.expAmbiguous)
			}
		})
	}

	t.Run("exact match wins over slug siblings", func(t *testing.T) {
		resolved, ambiguous := resolveRef("web-app", []string{"Web App", "web-app"})
		if resolved != "web-app" || ambiguous != nil {
			t.Errorf("expected exact match 'web-app', got %q (ambiguous %v)", resolved, ambiguous)
		}
	})

	t.Run("ambiguous slug", func(t *testing.T) {
		resolved, ambiguous := resolveRef("web-app", []string{"Web App", "Web App!"})
		if resolved != "" {
			t.Errorf("expected no resolution, got %q", resolved)
		}
		if len(ambiguous) != 2 {
			t.Errorf("expected 2 ambiguous matches, got %v", ambiguous)
		}
	})
}

func TestExtractRefSlugs(t *testing.T) {
	src := `spec_version = "0.4.0"
threatmodel "shallow" {
  author = "@xntrik"

  information_asset "Customer Data" {
    description = "pii"
  }

  data_flow_diagram_v2 "dfd" {
    process "Web App" {}
    external_element "End User" {}

    trust_zone "Internal Zone" {
      data_store "User DB" {}
    }
  }

  data_flow_diagram {
    process "Legacy Proc" {}
  }
}
`

	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL([]byte(src), "test.hcl")
	if diags.HasErrors() {
		t.Fatalf("error parsing test HCL: %s", diags)
	}

	refs := extractRefSlugs(f)

	// Namespace keys are underscore slugs, matching the threatmodel id
	// derivation convention rather than the OTM exporter's kebab ids.
	expected := map[string][]string{
		"information_asset": {"customer_data"},
		"process":           {"web_app", "legacy_proc"},
		"external_element":  {"end_user"},
		// "User DB" slugs to "user_d_b": the algorithm splits acronym runs
		// per uppercase letter.
		"data_store": {"user_d_b"},
		"trust_zone": {"internal_zone"},
	}

	for kind, slugs := range expected {
		for _, slug := range slugs {
			if _, ok := refs[kind][slug]; !ok {
				t.Errorf("expected %s namespace to contain slug '%s', got %v", kind, slug, refs[kind])
			}
		}
	}
}

func TestParseHCLFileWithSlugRefs(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLFile("./testdata/tm-slugrefs.hcl", false)
	if err != nil {
		t.Fatalf("Error parsing slug-ref TM file: %s", err)
	}

	tm := tmParser.GetWrapped().Threatmodels[0]

	// A dot-notation information_asset reference resolves to the canonical name
	if got := tm.Threats[0].InformationAssetRefs[0]; got != "Customer Data" {
		t.Errorf("threat information_asset_refs = %q, want 'Customer Data'", got)
	}

	dfd := tm.DataFlowDiagrams[0]

	for _, pr := range dfd.Processes {
		if pr.Name == "Backend Worker" && pr.TrustZone != "Internal Zone" {
			t.Errorf("Backend Worker trust_zone = %q, want 'Internal Zone'", pr.TrustZone)
		}
	}

	userDb := dfd.DataStores[0]
	if userDb.IaLink != "Customer Data" {
		t.Errorf("User DB information_asset = %q, want 'Customer Data'", userDb.IaLink)
	}
	if userDb.TrustZone != "Internal Zone" {
		t.Errorf("User DB trust_zone = %q, want 'Internal Zone'", userDb.TrustZone)
	}

	batchJob := dfd.TrustZones[0].Processes[0]
	if batchJob.TrustZone != "Internal Zone" {
		t.Errorf("Batch Job trust_zone = %q, want 'Internal Zone'", batchJob.TrustZone)
	}

	expFlows := map[string][2]string{
		"https": {"End User", "Web App"},
		"sql":   {"Web App", "User Database"},
		"queue": {"Web App", "Backend Worker"},
	}

	for _, flow := range dfd.Flows {
		exp, ok := expFlows[flow.Name]
		if !ok {
			t.Errorf("unexpected flow '%s'", flow.Name)
			continue
		}
		if flow.From != exp[0] || flow.To != exp[1] {
			t.Errorf("flow '%s' = %q -> %q, want %q -> %q", flow.Name, flow.From, flow.To, exp[0], exp[1])
		}
	}
}

func TestParseHCLRawSlugRefAmbiguous(t *testing.T) {
	tmRaw := `spec_version = "` + Version + `"
threatmodel "amb" {
  author = "@xntrik"

  information_asset "Web App" {
    description = "a"
  }

  information_asset "Web App!" {
    description = "b"
  }

  threat "t" {
    description            = "steal"
    information_asset_refs = ["web-app"]
  }
}
`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLRaw([]byte(tmRaw))
	if err == nil {
		t.Fatalf("Expected an ambiguity error, got nil")
	}

	if !strings.Contains(err.Error(), "ambiguous information_asset reference 'web-app'") {
		t.Errorf("Expected ambiguous reference error, got: %s", err)
	}
}

func TestParseHCLRawFlowSlugAmbiguous(t *testing.T) {
	tmRaw := `spec_version = "` + Version + `"
threatmodel "amb flows" {
  author = "@xntrik"

  data_flow_diagram_v2 "dfd" {
    process "Web App" {}
    external_element "Web App!" {}
    data_store "DB" {}

    flow "f" {
      from = "web-app"
      to   = "DB"
    }
  }
}
`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLRaw([]byte(tmRaw))
	if err == nil {
		t.Fatalf("Expected an ambiguity error, got nil")
	}

	if !strings.Contains(err.Error(), "ambiguous from connection 'web-app'") {
		t.Errorf("Expected ambiguous from connection error, got: %s", err)
	}

	// The ambiguity gates the generic wiring error, so it isn't double-reported
	if strings.Contains(err.Error(), "invalid from connection") {
		t.Errorf("Ambiguous flow should not also report an invalid connection, got: %s", err)
	}
}

func TestParseHCLRawTrustZoneSlugAmbiguous(t *testing.T) {
	tmRaw := `spec_version = "` + Version + `"
threatmodel "amb zones" {
  author = "@xntrik"

  data_flow_diagram_v2 "dfd" {
    process "Web App" {
      trust_zone = "internal-zone"
    }

    trust_zone "Internal Zone" {}
    trust_zone "Internal Zone!" {}
  }
}
`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLRaw([]byte(tmRaw))
	if err == nil {
		t.Fatalf("Expected an ambiguity error, got nil")
	}

	if !strings.Contains(err.Error(), "ambiguous trust_zone 'internal-zone' on 'Web App'") {
		t.Errorf("Expected ambiguous trust_zone error, got: %s", err)
	}
}

func TestParseHCLRawUnknownDotRef(t *testing.T) {
	tmRaw := `spec_version = "` + Version + `"
threatmodel "unknown ref" {
  author = "@xntrik"

  data_flow_diagram_v2 "dfd" {
    process "Web App" {}
    data_store "DB" {}

    flow "f" {
      from = process.nope
      to   = "DB"
    }
  }
}
`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLRaw([]byte(tmRaw))
	if err == nil {
		t.Fatalf("Expected a decode error for unknown dot reference, got nil")
	}

	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("Expected error to mention the unknown slug 'nope', got: %s", err)
	}
}

func TestParseHCLRawIndexSyntaxRef(t *testing.T) {
	// Slugs that aren't valid HCL identifiers (here: leading digit) are still
	// reachable via index syntax on the namespace object.
	tmRaw := `spec_version = "` + Version + `"
threatmodel "index ref" {
  author = "@xntrik"

  data_flow_diagram_v2 "dfd" {
    process "3rd Party Gateway" {}
    data_store "DB" {}

    flow "f" {
      from = process["3rd_party_gateway"]
      to   = "DB"
    }
  }
}
`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseHCLRaw([]byte(tmRaw))
	if err != nil {
		t.Fatalf("Error parsing TM with index-syntax ref: %s", err)
	}

	flow := tmParser.GetWrapped().Threatmodels[0].DataFlowDiagrams[0].Flows[0]
	if flow.From != "3rd Party Gateway" {
		t.Errorf("flow from = %q, want '3rd Party Gateway'", flow.From)
	}
}

func TestParseHCLRawSlugRefsJSON(t *testing.T) {
	tmRaw := `{
  "spec_version": "` + Version + `",
  "threatmodel": {
    "json slugs": {
      "author": "@xntrik",
      "information_asset": {
        "Customer Data": {
          "description": "pii"
        }
      },
      "threat": {
        "t": {
          "description": "steal",
          "information_asset_refs": ["customer-data"]
        }
      }
    }
  }
}`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseJSONRaw([]byte(tmRaw))
	if err != nil {
		t.Fatalf("Error parsing JSON TM with slug refs: %s", err)
	}

	tm := tmParser.GetWrapped().Threatmodels[0]
	if got := tm.Threats[0].InformationAssetRefs[0]; got != "Customer Data" {
		t.Errorf("threat information_asset_refs = %q, want 'Customer Data'", got)
	}
}

package spec

import (
	"strings"
	"testing"
)

func parseExtendsTest(tb testing.TB, in string) (*ThreatmodelParser, error) {
	tb.Helper()

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)
	err := tmParser.ParseHCLRaw([]byte(in))
	return tmParser, err
}

func extendsFixture() string {
	return `threatmodel "Buildings" {
  id     = "buildings"
  author = "@xntrik"

  attributes {
    new_initiative  = false
    internet_facing = true
    initiative_size = "Small"
  }

  information_asset "visitor records" {
    description = "Who came in and when"
  }

  usecase {
    description = "Visitors tour the building"
  }

  exclusion {
    description = "Aerial attack is out of scope"
  }

  third_party_dependency "community watch" {
    description       = "Neighbourhood watch"
    uptime_dependency = "degraded"
  }

  threat "Break-in" {
    description = "Someone forces a door"

    control "Guards" {
      implemented = true
      description = "Guards patrol the site"
    }
  }
}

threatmodel "Tower of London" {
  id      = "buildings.tower"
  extends = "buildings"
  author  = "@xntrik"

  threat "Crown theft" {
    description = "Someone steals the crown"
  }
}
`
}

func TestExtendsInheritsCollections(t *testing.T) {
	tmParser, err := parseExtendsTest(t, extendsFixture())
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	var child *Threatmodel
	for i := range tmParser.GetWrapped().Threatmodels {
		if tmParser.GetWrapped().Threatmodels[i].Id == "buildings.tower" {
			child = &tmParser.GetWrapped().Threatmodels[i]
		}
	}
	if child == nil {
		t.Fatal("child threat model not found")
	}

	if len(child.Threats) != 2 {
		t.Errorf("expected child to have its own threat plus the inherited one, got %d", len(child.Threats))
	}
	foundInherited := false
	for _, th := range child.Threats {
		if th.Name == "Break-in" {
			foundInherited = true
		}
	}
	if !foundInherited {
		t.Errorf("expected inherited threat 'Break-in' on the child")
	}

	if len(child.InformationAssets) != 1 || child.InformationAssets[0].Name != "visitor records" {
		t.Errorf("expected inherited information asset, got %+v", child.InformationAssets)
	}
	if len(child.UseCases) != 1 {
		t.Errorf("expected inherited usecase, got %d", len(child.UseCases))
	}
	if len(child.Exclusions) != 1 {
		t.Errorf("expected inherited exclusion, got %d", len(child.Exclusions))
	}
	if len(child.ThirdPartyDependencies) != 1 {
		t.Errorf("expected inherited third_party_dependency, got %d", len(child.ThirdPartyDependencies))
	}

	if child.Attributes == nil || !child.Attributes.InternetFacing {
		t.Errorf("expected inherited attributes block, got %+v", child.Attributes)
	}

	if child.Description != "" {
		t.Errorf("scalars must not inherit; child description = %q", child.Description)
	}
}

func TestExtendsChildOverrides(t *testing.T) {
	in := `threatmodel "Buildings" {
  id     = "buildings"
  author = "@xntrik"

  threat "Break-in" {
    description = "Someone forces a door"
  }
}

threatmodel "Tower of London" {
  id      = "buildings.tower"
  extends = "buildings"
  author  = "@xntrik"

  attributes {
    new_initiative  = true
    internet_facing = false
    initiative_size = "Small"
  }

  threat "Break-in" {
    description = "Someone forces a portcullis"
  }
}
`
	tmParser, err := parseExtendsTest(t, in)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	child := &tmParser.GetWrapped().Threatmodels[1]
	if len(child.Threats) != 1 {
		t.Fatalf("expected the child's own threat only, got %d", len(child.Threats))
	}
	if child.Threats[0].Description != "Someone forces a portcullis" {
		t.Errorf("expected the child's version to win, got %q", child.Threats[0].Description)
	}
	if child.Attributes == nil || child.Attributes.InternetFacing {
		t.Errorf("expected the child's own attributes block to win, got %+v", child.Attributes)
	}
}

func TestExtendsChain(t *testing.T) {
	in := `threatmodel "Org" {
  id     = "org"
  author = "@xntrik"

  threat "Phishing" {
    description = "Someone phishes staff"
  }
}

threatmodel "Buildings" {
  id      = "org.buildings"
  extends = "org"
  author  = "@xntrik"

  threat "Break-in" {
    description = "Someone forces a door"
  }
}

threatmodel "Tower of London" {
  id      = "org.buildings.tower"
  extends = "org.buildings"
  author  = "@xntrik"
}
`
	tmParser, err := parseExtendsTest(t, in)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	grandchild := &tmParser.GetWrapped().Threatmodels[2]
	if len(grandchild.Threats) != 2 {
		t.Fatalf("expected threats inherited through the chain, got %d", len(grandchild.Threats))
	}
}

func TestExtendsErrors(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"unknown_target",
			`threatmodel "Tower of London" {
  extends = "nope"
  author  = "@xntrik"
}`,
			"extends references unknown threat model id 'nope'",
		},
		{
			"self_extends",
			`threatmodel "Tower of London" {
  id      = "tower"
  extends = "tower"
  author  = "@xntrik"
}`,
			"extends cycle",
		},
		{
			"mutual_cycle",
			`threatmodel "A" {
  id      = "a"
  extends = "b"
  author  = "@xntrik"
}
threatmodel "B" {
  id      = "b"
  extends = "a"
  author  = "@xntrik"
}`,
			"extends cycle",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseExtendsTest(t, tc.in)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

package spec

import (
	"strings"
	"testing"
)

func TestValidIdentifier(t *testing.T) {
	cases := []struct {
		in  string
		exp bool
	}{
		{"tower_of_london", true},
		{"a", true},
		{"tm2_one", true},
		{"apps.tower", true},
		{"apps.web.frontend", true},
		{"", false},
		{"Tower_of_London", false},
		{"tower-of-london", false},
		{"3rd_party", false},
		{"_leading", false},
		{"has space", false},
		{".apps", false},
		{"apps.", false},
		{"apps..tower", false},
		{"apps.3rd", false},
		{"apps.Tower", false},
	}

	for _, tc := range cases {
		if got := ValidIdentifier(tc.in); got != tc.exp {
			t.Errorf("ValidIdentifier(%q) = %v, expected %v", tc.in, got, tc.exp)
		}
	}
}

func TestDeriveIdentifier(t *testing.T) {
	cases := []struct {
		in  string
		exp string
	}{
		{"Tower of London", "tower_of_london"},
		{"tm tm1 two", "tm_tm1_two"},
		{"Fort Knox", "fort_knox"},
	}

	for _, tc := range cases {
		if got := DeriveIdentifier(tc.in); got != tc.exp {
			t.Errorf("DeriveIdentifier(%q) = %q, expected %q", tc.in, got, tc.exp)
		}
	}
}

func TestIdentifierPrefixes(t *testing.T) {
	cases := []struct {
		in  string
		exp []string
	}{
		{"tower", nil},
		{"apps.tower", []string{"apps"}},
		{"apps.web.frontend", []string{"apps", "apps.web"}},
	}

	for _, tc := range cases {
		got := IdentifierPrefixes(tc.in)
		if len(got) != len(tc.exp) {
			t.Errorf("IdentifierPrefixes(%q) = %v, expected %v", tc.in, got, tc.exp)
			continue
		}
		for i := range got {
			if got[i] != tc.exp[i] {
				t.Errorf("IdentifierPrefixes(%q) = %v, expected %v", tc.in, got, tc.exp)
				break
			}
		}
	}
}

func TestThreatmodelIdentifier(t *testing.T) {
	tm := &Threatmodel{Name: "Tower of London"}
	if got := tm.Identifier(); got != "tower_of_london" {
		t.Errorf("expected derived identifier, got %q", got)
	}

	tm.Id = "legacy_tower"
	if got := tm.Identifier(); got != "legacy_tower" {
		t.Errorf("expected declared id to win, got %q", got)
	}
}

func TestParseThreatmodelIds(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string // expected error substring; empty means must parse
	}{
		{
			"valid_id",
			`threatmodel "Tower of London" {
  id     = "tower"
  author = "@xntrik"
}`,
			"",
		},
		{
			"invalid_id_dashes",
			`threatmodel "Tower of London" {
  id     = "tower-of-london"
  author = "@xntrik"
}`,
			"invalid id 'tower-of-london'",
		},
		{
			"invalid_id_leading_digit",
			`threatmodel "3rd Party Gateway" {
  id     = "3rd_party_gateway"
  author = "@xntrik"
}`,
			"invalid id '3rd_party_gateway'",
		},
		{
			"invalid_id_uppercase",
			`threatmodel "Tower of London" {
  id     = "Tower"
  author = "@xntrik"
}`,
			"invalid id 'Tower'",
		},
		{
			"duplicate_ids",
			`threatmodel "Tower of London" {
  id     = "tower"
  author = "@xntrik"
}
threatmodel "Fort Knox" {
  id     = "tower"
  author = "@xntrik"
}`,
			"duplicate id 'tower'",
		},
		{
			"distinct_ids",
			`threatmodel "Tower of London" {
  id     = "tower"
  author = "@xntrik"
}
threatmodel "Fort Knox" {
  id     = "fort"
  author = "@xntrik"
}`,
			"",
		},
		{
			"nested_ids",
			`threatmodel "Tower of London" {
  id     = "apps.tower"
  author = "@xntrik"
}
threatmodel "Bridge of London" {
  id     = "apps.bridge"
  author = "@xntrik"
}
threatmodel "The VPC" {
  id     = "infra.network.vpc"
  author = "@xntrik"
}`,
			"",
		},
		{
			"id_is_anothers_namespace",
			`threatmodel "Apps Portfolio" {
  id     = "apps"
  author = "@xntrik"
}
threatmodel "Tower of London" {
  id     = "apps.tower"
  author = "@xntrik"
}`,
			"id 'apps' is the namespace of id 'apps.tower'",
		},
		{
			"namespace_collision_order_independent",
			`threatmodel "Tower of London" {
  id     = "apps.tower"
  author = "@xntrik"
}
threatmodel "Apps Portfolio" {
  id     = "apps"
  author = "@xntrik"
}`,
			"id 'apps' is the namespace of id 'apps.tower'",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseHCLRaw([]byte(tc.in))

			if tc.exp == "" {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.exp)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
		})
	}
}

func TestThreatmodelIdRoundTrip(t *testing.T) {
	in := `threatmodel "Tower of London" {
  id     = "tower"
  author = "@xntrik"
}`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)
	if err := tmParser.ParseHCLRaw([]byte(in)); err != nil {
		t.Fatal(err)
	}

	tm := tmParser.GetWrapped().Threatmodels[0]
	if tm.Id != "tower" {
		t.Errorf("expected parsed id 'tower', got %q", tm.Id)
	}

	out := string(encodeWrappedToHCL(tmParser.GetWrapped()))
	if !strings.Contains(out, `"tower"`) || !strings.Contains(out, "id") {
		t.Errorf("expected re-encoded HCL to include the id, got:\n%s", out)
	}

	// A model without a declared id must not emit an empty id attribute.
	tmParser2 := NewThreatmodelParser(defaultCfg)
	if err := tmParser2.ParseHCLRaw([]byte(`threatmodel "Fort Knox" {
  author = "@xntrik"
}`)); err != nil {
		t.Fatal(err)
	}
	out2 := string(encodeWrappedToHCL(tmParser2.GetWrapped()))
	if strings.Contains(out2, "id") {
		t.Errorf("expected no id attribute when none declared, got:\n%s", out2)
	}
}

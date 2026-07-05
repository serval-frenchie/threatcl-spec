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
		{"", false},
		{"Tower_of_London", false},
		{"tower-of-london", false},
		{"3rd_party", false},
		{"_leading", false},
		{"has space", false},
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
			"explicit_empty_id",
			`threatmodel "Tower of London" {
  id     = ""
  author = "@xntrik"
}`,
			"id must not be empty when declared",
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

func TestParseJSONExplicitEmptyId(t *testing.T) {
	in := `{"threatmodel": {"Tower of London": {"id": "", "author": "@xntrik"}}}`

	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseJSONRaw([]byte(in))
	if err == nil {
		t.Fatalf("expected an error for explicit empty id, got none")
	}
	if !strings.Contains(err.Error(), "id must not be empty when declared") {
		t.Errorf("expected empty-id error, got: %s", err)
	}
}

func TestValidateUniqueIdentifiers(t *testing.T) {
	cases := []struct {
		name string
		tms  []Threatmodel
		exp  string // expected error substring; empty means valid
	}{
		{
			"distinct declared and derived",
			[]Threatmodel{
				{Name: "Tower of London", Id: "tower"},
				{Name: "Fort Knox"},
			},
			"",
		},
		{
			"duplicate declared ids",
			[]Threatmodel{
				{Name: "Tower of London", Id: "tower"},
				{Name: "Fort Knox", Id: "tower"},
			},
			"identifier 'tower' collides with TM 'Tower of London'",
		},
		{
			"declared id collides with derived identifier",
			[]Threatmodel{
				{Name: "Fort Knox"},
				{Name: "Tower of London", Id: "fort_knox"},
			},
			"identifier 'fort_knox' collides with TM 'Fort Knox'",
		},
		{
			"derived identifiers collide across renamed-alike models",
			[]Threatmodel{
				{Name: "Fort Knox"},
				{Name: "Fort Knox!"},
			},
			"identifier 'fort_knox' collides with TM 'Fort Knox'",
		},
		{
			"invalid declared id",
			[]Threatmodel{
				{Name: "Tower of London", Id: "Tower"},
			},
			"invalid id 'Tower'",
		},
		{
			"nameless idless models are skipped",
			[]Threatmodel{
				{},
				{},
			},
			"",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateUniqueIdentifiers(tc.tms)
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

func TestAddTMAndWriteIdValidation(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	t.Run("invalid id rejected", func(t *testing.T) {
		tmParser := NewThreatmodelParser(defaultCfg)
		var out strings.Builder
		err := tmParser.AddTMAndWrite(Threatmodel{Name: "Tower", Id: "Tower-Bad"}, &out, false)
		if err == nil || !strings.Contains(err.Error(), "invalid id 'Tower-Bad'") {
			t.Errorf("expected invalid id error, got: %v", err)
		}
		if out.Len() != 0 {
			t.Errorf("expected nothing written on validation failure, got: %s", out.String())
		}
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		tmParser := NewThreatmodelParser(defaultCfg)
		if err := tmParser.ParseHCLRaw([]byte(`threatmodel "Tower of London" {
  id     = "tower"
  author = "@xntrik"
}`)); err != nil {
			t.Fatal(err)
		}

		var out strings.Builder
		err := tmParser.AddTMAndWrite(Threatmodel{Name: "Fort Knox", Id: "tower"}, &out, false)
		if err == nil || !strings.Contains(err.Error(), "duplicate id 'tower'") {
			t.Errorf("expected duplicate id error, got: %v", err)
		}
	})

	t.Run("valid id accepted", func(t *testing.T) {
		tmParser := NewThreatmodelParser(defaultCfg)
		var out strings.Builder
		err := tmParser.AddTMAndWrite(Threatmodel{Name: "Fort Knox", Id: "fort", Author: "@xntrik"}, &out, false)
		if err != nil {
			t.Fatalf("unexpected error: %s", err)
		}
		if !strings.Contains(out.String(), `"fort"`) {
			t.Errorf("expected written HCL to include the id, got: %s", out.String())
		}
	})
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

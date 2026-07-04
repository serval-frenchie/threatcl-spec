package spec

import (
	"reflect"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// reparse renders the parser's wrapped state to HCL, parses it back into a
// fresh parser, and returns the new parser.
func reparse(t *testing.T, p *ThreatmodelParser) *ThreatmodelParser {
	t.Helper()
	out := p.HclString()
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p2 := NewThreatmodelParser(cfg)
	if err := p2.ParseHCLRaw([]byte(out)); err != nil {
		t.Fatalf("round-trip parse failed:\n--- HCL ---\n%s\n--- ERR ---\n%s", out, err)
	}
	return p2
}

func TestRoundTripControlBlock(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Repro" {
  author = "tester"
  threat "SQLi" {
    description = "Local SQL injection"
    impacts = ["Confidentiality"]
    control "Parameterized Queries" {
      description = "Use prepared statements"
      implemented = true
      risk_reduction = 90
    }
  }
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	out := p.HclString()
	if !strings.Contains(out, `control "Parameterized Queries"`) {
		t.Errorf("expected proper block syntax, got:\n%s", out)
	}
	if strings.Contains(out, "control = [") {
		t.Errorf("output still uses list-of-objects encoding:\n%s", out)
	}

	p2 := reparse(t, p)
	tm := p2.GetWrapped().Threatmodels[0]
	if len(tm.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(tm.Threats))
	}
	th := tm.Threats[0]
	if len(th.Controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(th.Controls))
	}
	c := th.Controls[0]
	if c.Name != "Parameterized Queries" {
		t.Errorf("control name = %q, want %q", c.Name, "Parameterized Queries")
	}
	if !c.Implemented {
		t.Errorf("control.Implemented = false, want true")
	}
	if c.RiskReduction != 90 {
		t.Errorf("control.RiskReduction = %d, want 90", c.RiskReduction)
	}
	if c.Description != "Use prepared statements" {
		t.Errorf("control.Description = %q", c.Description)
	}
}

func TestRoundTripNoNoise(t *testing.T) {
	src := `spec_version = "` + Version + `"
threatmodel "minimal" {
  author = "x"
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("parse failed: %s", err)
	}

	out := p.HclString()
	for _, banned := range []string{
		"imports",
		"created_at",
		"updated_at",
		"= null",
		"stride",
		"information_asset_refs",
		"control_imports",
		"expanded_control",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("output contains unwanted token %q:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, `threatmodel "minimal"`) {
		t.Errorf("missing threatmodel block:\n%s", out)
	}
	if !strings.Contains(out, `author = "x"`) {
		t.Errorf("missing author attribute:\n%s", out)
	}
}

func TestRoundTripAllBlockTypes(t *testing.T) {
	src := `spec_version = "` + Version + `"

backend "primary" {
  organization = "acme"
  threatmodel = "tm-main"
  project = "core"
}

component "control" "shared_auth" {
  description = "Shared auth control"
  implemented = true
  risk_reduction = 50
}

variable "env" {
  value = "prod"
}

threatmodel "full" {
  author = "@me"
  description = "everything"

  attributes {
    new_initiative = true
    internet_facing = false
    initiative_size = "small"
  }

  additional_attribute "segment" {
    value = "dmz"
  }

  information_asset "creds" {
    description = "stored credentials"
    information_classification = "Restricted"
  }

  usecase {
    description = "users do things"
  }

  exclusion {
    description = "out of scope: kernel bugs"
  }

  third_party_dependency "IdP" {
    description = "external idp"
    uptime_dependency = "degraded"
  }

  threat "t1" {
    description = "t1 description"
    impacts = ["Confidentiality"]

    proposed_control {
      description = "do thing"
      implemented = true
    }

    control "c1" {
      description = "c1 desc"
      implemented = true
      risk_reduction = 80
      attribute "owner" {
        value = "team-a"
      }
    }
  }

  data_flow_diagram_v2 "dfd1" {
    process "p1" {}
    external_element "user" {}
    data_store "db" {
      information_asset = "creds"
    }
    flow "https" {
      from = "user"
      to = "p1"
    }
    trust_zone "secure" {
      process "p2" {}
    }
  }
}

threatmodel "legacy_dfd_owner" {
  author = "@me"

  data_flow_diagram {
    process "lp" {}
    external_element "lext" {}
    flow "tcp" {
      from = "lext"
      to = "lp"
    }
  }
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	p2 := reparse(t, p)
	w := p2.GetWrapped()

	if len(w.Backends) != 1 || w.Backends[0].BackendOrg != "acme" {
		t.Errorf("backend lost: %+v", w.Backends)
	}
	if len(w.Components) != 1 || w.Components[0].ComponentName != "shared_auth" {
		t.Errorf("component lost: %+v", w.Components)
	}
	if len(w.Variables) != 1 || w.Variables[0].VariableValue != "prod" {
		t.Errorf("variable lost: %+v", w.Variables)
	}
	if len(w.Threatmodels) != 2 {
		t.Fatalf("expected 2 threatmodels, got %d", len(w.Threatmodels))
	}

	tm := w.Threatmodels[0]
	if tm.Attributes == nil || !strings.EqualFold(tm.Attributes.InitiativeSize, "small") {
		t.Errorf("attributes block lost: %+v", tm.Attributes)
	}
	if len(tm.AdditionalAttributes) != 1 || tm.AdditionalAttributes[0].Value != "dmz" {
		t.Errorf("additional_attribute lost: %+v", tm.AdditionalAttributes)
	}
	if len(tm.InformationAssets) != 1 || tm.InformationAssets[0].Name != "creds" {
		t.Errorf("information_asset lost: %+v", tm.InformationAssets)
	}
	if len(tm.UseCases) != 1 {
		t.Errorf("usecase lost: %+v", tm.UseCases)
	}
	if len(tm.Exclusions) != 1 {
		t.Errorf("exclusion lost: %+v", tm.Exclusions)
	}
	if len(tm.ThirdPartyDependencies) != 1 || tm.ThirdPartyDependencies[0].Name != "IdP" {
		t.Errorf("third_party_dependency lost: %+v", tm.ThirdPartyDependencies)
	}
	if len(tm.Threats) != 1 {
		t.Fatalf("expected 1 threat, got %d", len(tm.Threats))
	}
	threat := tm.Threats[0]
	if len(threat.ProposedControls) != 1 || !threat.ProposedControls[0].Implemented {
		t.Errorf("proposed_control lost: %+v", threat.ProposedControls)
	}
	if len(threat.Controls) != 1 || threat.Controls[0].Name != "c1" {
		t.Fatalf("control lost: %+v", threat.Controls)
	}
	if len(threat.Controls[0].Attributes) != 1 || threat.Controls[0].Attributes[0].Name != "owner" {
		t.Errorf("control attribute lost: %+v", threat.Controls[0].Attributes)
	}
	if len(tm.DataFlowDiagrams) != 1 {
		t.Fatalf("data_flow_diagram_v2 lost: %+v", tm.DataFlowDiagrams)
	}
	dfd := tm.DataFlowDiagrams[0]
	if len(dfd.Processes) != 1 || len(dfd.ExternalElements) != 1 ||
		len(dfd.DataStores) != 1 || len(dfd.Flows) != 1 || len(dfd.TrustZones) != 1 {
		t.Errorf("dfd children lost: %+v", dfd)
	}
	if len(dfd.TrustZones[0].Processes) != 1 {
		t.Errorf("trust_zone nested process lost: %+v", dfd.TrustZones[0])
	}

	tm2 := w.Threatmodels[1]
	// The legacy data_flow_diagram block gets shifted into DataFlowDiagrams
	// at parse time (see shiftLegacyDfd), so check the shifted form rather
	// than LegacyDfd which is cleared after the shift.
	if len(tm2.DataFlowDiagrams) != 1 {
		t.Fatalf("legacy dfd not shifted: %+v", tm2)
	}
	ldfd := tm2.DataFlowDiagrams[0]
	if len(ldfd.Processes) != 1 || len(ldfd.ExternalElements) != 1 || len(ldfd.Flows) != 1 {
		t.Errorf("legacy dfd children lost: %+v", ldfd)
	}
}

// TestRoundTripSkipsNilControlEntry ensures a nil pointer inside a block
// slice (e.g. a nil *Control appended programmatically) is skipped rather
// than panicking or emitting an empty block.
func TestRoundTripSkipsNilControlEntry(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "nilblock" {
  author = "tester"
  threat "t" {
    description = "d"
    control "real" {
      description = "real control"
    }
  }
}
`
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	// Splice a nil entry into the block slice, as programmatic callers can.
	th := p.GetWrapped().Threatmodels[0].Threats[0]
	th.Controls = append([]*Control{nil}, th.Controls...)

	out := p.HclString()
	if !strings.Contains(out, `control "real"`) {
		t.Errorf("real control block missing:\n%s", out)
	}
	if got := strings.Count(out, "control "); got != 1 {
		t.Errorf("expected exactly 1 control block, got %d:\n%s", got, out)
	}

	p2 := reparse(t, p)
	controls := p2.GetWrapped().Threatmodels[0].Threats[0].Controls
	if len(controls) != 1 || controls[0].Name != "real" {
		t.Errorf("round-trip controls = %+v, want single %q", controls, "real")
	}
}

// hclEncodeIfaceHolder gives tests a reflect.Value whose Kind is Interface
// (reflect.ValueOf on a bare interface{} unwraps to the concrete type).
type hclEncodeIfaceHolder struct {
	I interface{}
}

func hclEncodeIfaceValue(v interface{}) reflect.Value {
	h := hclEncodeIfaceHolder{I: v}
	return reflect.ValueOf(&h).Elem().Field(0)
}

func TestIsZeroForHclAllKinds(t *testing.T) {
	nonNilStr := "x"
	tests := []struct {
		name string
		val  reflect.Value
		want bool
	}{
		{"empty string", reflect.ValueOf(""), true},
		{"non-empty string", reflect.ValueOf("a"), false},
		{"false bool", reflect.ValueOf(false), true},
		{"true bool", reflect.ValueOf(true), false},
		{"zero int", reflect.ValueOf(0), true},
		{"non-zero int", reflect.ValueOf(7), false},
		{"zero int64", reflect.ValueOf(int64(0)), true},
		{"non-zero int64", reflect.ValueOf(int64(-3)), false},
		{"zero uint", reflect.ValueOf(uint(0)), true},
		{"non-zero uint", reflect.ValueOf(uint(9)), false},
		{"zero uint8", reflect.ValueOf(uint8(0)), true},
		{"non-zero uint8", reflect.ValueOf(uint8(1)), false},
		{"zero float64", reflect.ValueOf(float64(0)), true},
		{"non-zero float64", reflect.ValueOf(3.14), false},
		{"zero float32", reflect.ValueOf(float32(0)), true},
		{"non-zero float32", reflect.ValueOf(float32(1.5)), false},
		{"nil slice", reflect.ValueOf([]string(nil)), true},
		{"empty slice", reflect.ValueOf([]string{}), true},
		{"non-empty slice", reflect.ValueOf([]string{"a"}), false},
		{"nil map", reflect.ValueOf(map[string]string(nil)), true},
		{"empty map", reflect.ValueOf(map[string]string{}), true},
		{"non-empty map", reflect.ValueOf(map[string]string{"k": "v"}), false},
		{"nil pointer", reflect.ValueOf((*string)(nil)), true},
		{"non-nil pointer", reflect.ValueOf(&nonNilStr), false},
		{"nil interface", hclEncodeIfaceValue(nil), true},
		{"non-nil interface", hclEncodeIfaceValue("x"), false},
		{"zero struct", reflect.ValueOf(Risk{}), true},
		{"non-zero struct", reflect.ValueOf(Risk{Likelihood: "high"}), false},
		// Kinds outside the switch fall through to `return false`, even
		// when the value is that kind's zero value.
		{"zero complex (default case)", reflect.ValueOf(complex(0, 0)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isZeroForHcl(tc.val); got != tc.want {
				t.Errorf("isZeroForHcl(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestMakeCtyValueKinds(t *testing.T) {
	var nilFuncSlice []func()
	tests := []struct {
		name   string
		val    reflect.Value
		want   cty.Value
		wantOk bool
	}{
		{"string", reflect.ValueOf("hello"), cty.StringVal("hello"), true},
		{"bool", reflect.ValueOf(true), cty.True, true},
		{"int", reflect.ValueOf(42), cty.NumberIntVal(42), true},
		{"int64", reflect.ValueOf(int64(99)), cty.NumberIntVal(99), true},
		{"uint", reflect.ValueOf(uint(7)), cty.NumberIntVal(7), true},
		{"float64", reflect.ValueOf(1.5), cty.NumberFloatVal(1.5), true},
		{"string slice", reflect.ValueOf([]string{"a", "b"}),
			cty.ListVal([]cty.Value{cty.StringVal("a"), cty.StringVal("b")}), true},
		// A nil slice of a convertible element type emits an empty list
		// rather than null.
		{"nil string slice", reflect.ValueOf([]string(nil)),
			cty.ListValEmpty(cty.String), true},
		{"nil int slice", reflect.ValueOf([]int(nil)),
			cty.ListValEmpty(cty.Number), true},
		{"string map", reflect.ValueOf(map[string]string{"k": "v"}),
			cty.MapVal(map[string]cty.Value{"k": cty.StringVal("v")}), true},
		// Unconvertible types report !ok instead of emitting a value.
		{"func", reflect.ValueOf(func() {}), cty.NilVal, false},
		{"untagged struct", reflect.ValueOf(struct{ A string }{A: "x"}), cty.NilVal, false},
		// A nil slice whose element type is unconvertible falls through the
		// empty-list shortcut and then fails the general conversion.
		{"nil func slice", reflect.ValueOf(nilFuncSlice), cty.NilVal, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := makeCtyValue(tc.val)
			if ok != tc.wantOk {
				t.Fatalf("makeCtyValue(%s) ok = %v, want %v", tc.name, ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if !got.RawEquals(tc.want) {
				t.Errorf("makeCtyValue(%s) = %#v, want %#v", tc.name, got, tc.want)
			}
		})
	}
}

// hclEncodeBadAttr has a required attr whose type can't convert to cty; the
// encoder should skip it and keep the convertible attribute.
type hclEncodeBadAttr struct {
	Name string `hcl:"name"`
	Bad  func() `hcl:"bad"`
}

func TestEncodeBodyEdgeCases(t *testing.T) {
	t.Run("pointer to struct is dereferenced", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		v := &hclEncodeBadAttr{Name: "n1"}
		encodeBody(f.Body(), reflect.ValueOf(v))
		out := string(f.Bytes())
		if !strings.Contains(out, `name = "n1"`) {
			t.Errorf("expected name attribute, got:\n%s", out)
		}
	})

	t.Run("nil pointer emits nothing", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		encodeBody(f.Body(), reflect.ValueOf((*hclEncodeBadAttr)(nil)))
		if out := string(f.Bytes()); out != "" {
			t.Errorf("expected empty output, got:\n%s", out)
		}
	})

	t.Run("non-struct emits nothing", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		encodeBody(f.Body(), reflect.ValueOf("not a struct"))
		if out := string(f.Bytes()); out != "" {
			t.Errorf("expected empty output, got:\n%s", out)
		}
	})

	t.Run("unconvertible attr is skipped", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		encodeBody(f.Body(), reflect.ValueOf(hclEncodeBadAttr{Name: "n2", Bad: func() {}}))
		out := string(f.Bytes())
		if !strings.Contains(out, `name = "n2"`) {
			t.Errorf("expected name attribute, got:\n%s", out)
		}
		if strings.Contains(out, "bad") {
			t.Errorf("unconvertible attr should be skipped, got:\n%s", out)
		}
	})
}

// hclEncodeInnerBlock is a labelled block struct for direct emit tests.
type hclEncodeInnerBlock struct {
	Label string `hcl:"label,label"`
	Val   string `hcl:"val"`
}

func TestEmitBlockFieldEdgeCases(t *testing.T) {
	t.Run("nil pointer slice element is skipped", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		blocks := []*hclEncodeInnerBlock{nil, {Label: "keep", Val: "v"}}
		emitBlockField(f.Body(), "inner", reflect.ValueOf(blocks))
		out := string(f.Bytes())
		if !strings.Contains(out, `inner "keep"`) {
			t.Errorf("expected surviving block, got:\n%s", out)
		}
		if got := strings.Count(out, "inner "); got != 1 {
			t.Errorf("expected exactly 1 block, got %d:\n%s", got, out)
		}
	})

	t.Run("plain struct field emits a block", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		emitBlockField(f.Body(), "inner", reflect.ValueOf(hclEncodeInnerBlock{Label: "s", Val: "v"}))
		out := string(f.Bytes())
		if !strings.Contains(out, `inner "s"`) {
			t.Errorf("expected struct block, got:\n%s", out)
		}
		if !strings.Contains(out, `val = "v"`) {
			t.Errorf("expected block body attribute, got:\n%s", out)
		}
	})
}

func TestEmitOneBlockEdgeCases(t *testing.T) {
	t.Run("nil pointer emits nothing", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		emitOneBlock(f.Body(), "inner", reflect.ValueOf((*hclEncodeInnerBlock)(nil)))
		if out := string(f.Bytes()); out != "" {
			t.Errorf("expected empty output, got:\n%s", out)
		}
	})

	t.Run("non-struct emits nothing", func(t *testing.T) {
		f := hclwrite.NewEmptyFile()
		emitOneBlock(f.Body(), "inner", reflect.ValueOf(42))
		if out := string(f.Bytes()); out != "" {
			t.Errorf("expected empty output, got:\n%s", out)
		}
	})
}

func TestRoundTripStableEncoding(t *testing.T) {
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(tmTestValid)); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	first := p.HclString()
	p2 := reparse(t, p)
	second := p2.HclString()
	if first != second {
		t.Errorf("encoding is not stable across round-trips\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestRoundTripExistingFixture(t *testing.T) {
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseFile("./testdata/tm1.hcl", false); err != nil {
		t.Fatalf("initial parse failed: %s", err)
	}

	first := p.HclString()
	cfg2 := &ThreatmodelSpecConfig{}
	cfg2.setDefaults()
	p2 := NewThreatmodelParser(cfg2)
	if err := p2.ParseHCLRaw([]byte(first)); err != nil {
		t.Fatalf("round-trip parse failed:\n%s\n--- err ---\n%s", first, err)
	}
	second := p2.HclString()
	if first != second {
		t.Errorf("tm1.hcl encoding is not stable across round-trips")
	}
}

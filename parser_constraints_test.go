package spec

import (
	"fmt"
	"strings"
	"testing"
)

func TestControlStringConstraint(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		exp       []string
		invertexp bool
	}{
		{
			"old_version_and_no_control",
			"./testdata/tm1.hcl",
			[]string{"Deprecation warning: This threat model has defined `control`"},
			true,
		},
		{
			"old_version_and_control",
			"./testdata/tm-withimport.hcl",
			[]string{"Deprecation warning: This threat model has defined `control`"},
			false,
		},
		{
			"old_version_and_control_block",
			"./testdata/tm-constraint-proposed.hcl",
			[]string{"Deprecation warning: This threat model has defined `proposed_control`"},
			false,
		},
		{
			"old_dfd",
			"./testdata/tm-constraint-multidfd.hcl",
			[]string{"Deprecation warning: This threat model has a defined `data_flow_diagram`"},
			false,
		},
		{
			"old_version_and_expanded_control_block",
			"./testdata/constraintcov-expanded.hcl",
			[]string{"Deprecation warning: This threat model has defined `expanded_control`"},
			false,
		},
		{
			"multiple_constraints",
			"./testdata/tm-constraint-multiple.hcl",
			[]string{
				"Deprecation warning: This threat model has defined `control`",
				"Deprecation warning: This threat model has defined `proposed_control`",
				"Deprecation warning: This threat model has a defined `data_flow_diagram`",
			},
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			defaultCfg := &ThreatmodelSpecConfig{}
			defaultCfg.setDefaults()
			tmParser := NewThreatmodelParser(defaultCfg)

			err := tmParser.ParseFile(tc.in, false)
			if err != nil {
				t.Errorf("Error parsing hcl file: %s", err)
			}

			constraintMsg, err := VersionConstraints(tmParser.GetWrapped(), false)
			if err != nil {
				t.Errorf("Error parsing constraints: %s", err)
			}

			if !tc.invertexp {
				for _, exp := range tc.exp {
					if !strings.Contains(constraintMsg, exp) {
						t.Errorf("Expected %s to contain %s", constraintMsg, exp)
					}
				}
			} else {
				for _, exp := range tc.exp {
					if strings.Contains(constraintMsg, exp) {
						t.Errorf("Was not expecting %s to contain %s", constraintMsg, exp)
					}
				}
			}

		})
	}
}

func multiConstraintWarnings() []string {
	csb := &controlStringToBlock{}
	pcb := &proposedControlToBlock{}
	mdfd := &multiDfd{}

	return []string{
		fmt.Sprintf("[threatmodel: multi tm1] %s", csb.msg()),
		fmt.Sprintf("[threatmodel: multi tm2] %s", csb.msg()),
		fmt.Sprintf("[threatmodel: multi tm1] %s", pcb.msg()),
		fmt.Sprintf("[threatmodel: multi tm1] %s", mdfd.msg()),
	}
}

func TestVersionConstraintsDeterministic(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tm-constraint-multiple.hcl", false)
	if err != nil {
		t.Fatalf("Error parsing hcl file: %s", err)
	}

	exp := strings.Join(multiConstraintWarnings(), "\n")

	// Run repeatedly so any reintroduced iteration nondeterminism is caught
	for range 20 {
		constraintMsg, err := VersionConstraints(tmParser.GetWrapped(), false)
		if err != nil {
			t.Fatalf("Error parsing constraints: %s", err)
		}

		if constraintMsg != exp {
			t.Fatalf("Expected constraint message:\n%s\n\nGot:\n%s", exp, constraintMsg)
		}
	}
}

func TestConstraintCovAsOf(t *testing.T) {
	cases := []struct {
		name       string
		constraint hcltmConstraint
		exp        string
	}{
		{"control_string_to_block", &controlStringToBlock{}, "0.1.5"},
		{"proposed_control_to_block", &proposedControlToBlock{}, "0.1.5"},
		{"expanded_control_to_control", &expandedControlToControl{}, "0.1.17"},
		{"multi_dfd", &multiDfd{}, "0.1.6"},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if got := tc.constraint.asOf(); got != tc.exp {
				t.Errorf("Expected asOf %s, got %s", tc.exp, got)
			}

			// The deprecation message should reference the asOf version
			if !strings.Contains(tc.constraint.msg(), fmt.Sprintf("v%s", tc.exp)) {
				t.Errorf("Expected msg to mention v%s, got: %s", tc.exp, tc.constraint.msg())
			}
		})
	}
}

func TestConstraintCovEmitNoMatch(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/constraintcov-clean.hcl", false)
	if err != nil {
		t.Fatalf("Error parsing hcl file: %s", err)
	}

	// emit=true exercises the stdout path; the clean fixture matches no
	// constraints so nothing is actually printed
	constraintMsg, err := VersionConstraints(tmParser.GetWrapped(), true)
	if err != nil {
		t.Fatalf("Error parsing constraints: %s", err)
	}

	if constraintMsg != "" {
		t.Errorf("Expected no constraint warnings, got: %s", constraintMsg)
	}
}

func TestConstraintCovInvalidSpecVersion(t *testing.T) {
	tmw := &ThreatmodelWrapped{
		SpecVersion: "not-a-version",
	}

	constraintMsg, err := VersionConstraints(tmw, false)
	if err == nil {
		t.Error("Expected an error from VersionConstraints for an invalid spec version")
	} else if !strings.Contains(err.Error(), "malformed version") {
		t.Errorf("Expected malformed version error, got: %s", err)
	}

	if constraintMsg != "" {
		t.Errorf("Expected empty constraint message on error, got: %s", constraintMsg)
	}

	sb := &strings.Builder{}
	constraintMsg, err = VersionConstraintsToWriter(tmw, sb)
	if err == nil {
		t.Error("Expected an error from VersionConstraintsToWriter for an invalid spec version")
	} else if !strings.Contains(err.Error(), "malformed version") {
		t.Errorf("Expected malformed version error, got: %s", err)
	}

	if constraintMsg != "" {
		t.Errorf("Expected empty constraint message on error, got: %s", constraintMsg)
	}

	if sb.String() != "" {
		t.Errorf("Expected nothing written on error, got: %s", sb.String())
	}
}

func TestVersionConstraintsToWriter(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tm-constraint-multiple.hcl", false)
	if err != nil {
		t.Fatalf("Error parsing hcl file: %s", err)
	}

	sb := &strings.Builder{}
	constraintMsg, err := VersionConstraintsToWriter(tmParser.GetWrapped(), sb)
	if err != nil {
		t.Fatalf("Error parsing constraints: %s", err)
	}

	warnings := multiConstraintWarnings()

	exp := strings.Join(warnings, "\n")
	if constraintMsg != exp {
		t.Errorf("Expected constraint message:\n%s\n\nGot:\n%s", exp, constraintMsg)
	}

	expWritten := strings.Join(warnings, "\n") + "\n"
	if sb.String() != expWritten {
		t.Errorf("Expected written output:\n%s\n\nGot:\n%s", expWritten, sb.String())
	}
}

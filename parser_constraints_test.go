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

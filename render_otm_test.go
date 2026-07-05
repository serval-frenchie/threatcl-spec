package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKebab(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"empty",
			"",
			"",
		},
		{
			"message with space",
			"message with space",
			"message-with-space",
		},
		{
			"message start with dash",
			"-message with space",
			"message-with-space",
		},
		{
			"ThisIsATest",
			"ThisIsATest",
			"this-is-a-test",
		},
		{
			"message with space random characters",
			"message with space!#$%",
			"message-with-space",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.exp != Slugify(tc.in) {
				t.Errorf("'%s' should have been converted to '%s' but ended up being '%s'", tc.in, tc.exp, Slugify(tc.in))
			}
		})
	}
}

func TestKebabUnder(t *testing.T) {
	cases := []struct {
		name string
		in   string
		exp  string
	}{
		{
			"empty",
			"",
			"",
		},
		{
			"message with space",
			"message with space",
			"message_with_space",
		},
		{
			"message with space random characters",
			"message with space!#$%",
			"message_with_space",
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.exp != SlugifyUnderscore(tc.in) {
				t.Errorf("'%s' should have been converted to '%s' but ended up being '%s'", tc.in, tc.exp, SlugifyUnderscore(tc.in))
			}
		})
	}
}

func TestRenderOtm(t *testing.T) {
	tmAttr := &Attribute{}
	additionalAttr := &AdditionalAttribute{
		Name:  "Name",
		Value: "Value",
	}
	tm := &Threatmodel{
		Name:        "test",
		Author:      "x",
		DiagramLink: "http://linkieboop",
		Attributes:  tmAttr,
		Repository: []string{
			"https://github.com/threatcl/spec",
		},
	}
	tm.AdditionalAttributes = append(tm.AdditionalAttributes, additionalAttr)
	ia := &InformationAsset{
		Name:                      "blep",
		Source:                    "source",
		InformationClassification: "Confidential",
	}

	tm.InformationAssets = append(tm.InformationAssets, ia)
	controlAttribute := &ControlAttribute{
		Name:  "Name",
		Value: "Value",
	}
	control := &Control{
		Name:                "control name",
		ImplementationNotes: "implementation notes",
	}
	control.Attributes = append(control.Attributes, controlAttribute)
	threat := &Threat{
		Name:        "Attacker spoofs a user",
		Description: "threat description",
		Stride: []string{
			"Spoofing",
		},
		ImpactType: []string{
			"Confidentiality",
		},
	}
	threat.Controls = append(threat.Controls, control)
	tm.Threats = append(tm.Threats, threat)

	unnamedThreat := &Threat{
		Description: "unnamed threat description",
	}
	tm.Threats = append(tm.Threats, unnamedThreat)

	otmJson, err := tm.RenderOtm()
	if err != nil {
		t.Errorf("Error parsing model: %s", err)
	}

	jsonOut, err := json.Marshal(otmJson)
	if err != nil {
		t.Errorf("Error marshing into json: %s", err)
	}

	if !strings.Contains(string(jsonOut), "name\":\"test") {
		t.Errorf("Json (%s) didn't equal", string(jsonOut))
	}

	if !strings.Contains(string(jsonOut), "https://github.com/threatcl/spec") {
		t.Errorf("Json (%s) didn't include the repository attribute", string(jsonOut))
	}

	if len(otmJson.Assets) != 1 {
		t.Fatalf("Expected 1 asset but got %d", len(otmJson.Assets))
	}

	if otmJson.Assets[0].Attributes["information_classification"] != "Confidential" {
		t.Errorf("Asset attributes (%v) didn't include the information classification", otmJson.Assets[0].Attributes)
	}

	if otmJson.Assets[0].Attributes["source"] != "source" {
		t.Errorf("Asset attributes (%v) didn't include the source", otmJson.Assets[0].Attributes)
	}

	if len(otmJson.Threats) != 2 {
		t.Fatalf("Expected 2 threats but got %d", len(otmJson.Threats))
	}

	if otmJson.Threats[0].Name != "Attacker spoofs a user" {
		t.Errorf("Threat name should have been 'Attacker spoofs a user' but was '%s'", otmJson.Threats[0].Name)
	}

	if otmJson.Threats[0].Id != "attacker-spoofs-a-user" {
		t.Errorf("Threat id should have been 'attacker-spoofs-a-user' but was '%s'", otmJson.Threats[0].Id)
	}

	if otmJson.Threats[1].Name != "Threat 2" {
		t.Errorf("Unnamed threat should have fallen back to 'Threat 2' but was '%s'", otmJson.Threats[1].Name)
	}

	if otmJson.Threats[1].Id != "threat-2" {
		t.Errorf("Unnamed threat id should have been 'threat-2' but was '%s'", otmJson.Threats[1].Id)
	}

}

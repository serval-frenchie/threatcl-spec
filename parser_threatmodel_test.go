package spec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHCLFileWithIncluding(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app.hcl", false)

	// t.Logf("out1: '%s', out2: '%s'", out1, out2)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundIncludeduc := false
	foundSelfuc := false

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		t.Logf("tm: '%s'", tm.Name)
		if tm.Name == "Tower of London" {
			for _, uc := range tm.UseCases {
				if strings.Contains(uc.Description, "fetch the crown") {
					foundIncludeduc = true
				}

				if strings.Contains(uc.Description, "another uc perhaps") {
					foundSelfuc = true
				}
			}

			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Description, "I should be overriden") {
					foundOverwrittenIa = true
				}

			}
		}
	}

	if !foundSelfuc {
		t.Errorf("We didn't find our own use case")
	}

	if !foundIncludeduc {
		t.Errorf("We didn't find our included use case")
	}

	if foundOverwrittenIa {
		t.Errorf("We found an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemote(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingRemoteGit(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote2.hcl", false)

	if err != nil {
		t.Errorf("Error parsing legit TM file: %s", err)
	}

	foundOverwrittenIa := false

	for _, tm := range tmParser.GetWrapped().Threatmodels {
		if tm.Name == "Tower of London" {
			for _, ia := range tm.InformationAssets {
				if strings.Contains(ia.Name, "crown jewels") {
					foundOverwrittenIa = true
				}
			}
		}
	}

	if !foundOverwrittenIa {
		t.Errorf("We didn't find an IA that should have been overwritten")
	}

}

func TestParseHCLFileWithIncludingTooMany(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app2.hcl", false)

	if err == nil {
		t.Errorf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "incorrect number of threat models. Expected 1 but got 2") {
		t.Errorf("We should have an error about too many models")
	}
}

func TestTmaddcovIncludeMergesAndDedups(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-parent.hcl", false)

	if err != nil {
		t.Fatalf("Error parsing legit TM file: %s", err)
	}

	var tm *Threatmodel
	for i, candidate := range tmParser.GetWrapped().Threatmodels {
		if candidate.Name == "Coverage Castle" {
			tm = &tmParser.GetWrapped().Threatmodels[i]
		}
	}

	if tm == nil {
		t.Fatalf("We didn't find the parent threat model")
	}

	// Use cases: the parent's "shared use case" should suppress the
	// included duplicate, while "included-only use case" is merged in
	if len(tm.UseCases) != 2 {
		t.Errorf("Expected 2 use cases but got %d", len(tm.UseCases))
	}

	foundIncludedOnlyUc := false
	for _, uc := range tm.UseCases {
		if uc.Description == "included-only use case" {
			foundIncludedOnlyUc = true
		}
	}

	if !foundIncludedOnlyUc {
		t.Errorf("We didn't find the included-only use case")
	}

	// Exclusions: same dedup-by-description behaviour
	if len(tm.Exclusions) != 2 {
		t.Errorf("Expected 2 exclusions but got %d", len(tm.Exclusions))
	}

	foundIncludedOnlyExcl := false
	for _, excl := range tm.Exclusions {
		if excl.Description == "included-only exclusion" {
			foundIncludedOnlyExcl = true
		}
	}

	if !foundIncludedOnlyExcl {
		t.Errorf("We didn't find the included-only exclusion")
	}

	// Third party dependencies: dedup by name, keeping the parent's copy
	if len(tm.ThirdPartyDependencies) != 2 {
		t.Errorf("Expected 2 third party dependencies but got %d", len(tm.ThirdPartyDependencies))
	}

	for _, tpd := range tm.ThirdPartyDependencies {
		if tpd.Name == "shared tpd" && !strings.Contains(tpd.Description, "parent copy") {
			t.Errorf("The parent's 'shared tpd' should not have been overwritten")
		}
	}

	// DFDs: dedup by name, keeping the parent's copy
	if len(tm.DataFlowDiagrams) != 2 {
		t.Errorf("Expected 2 data flow diagrams but got %d", len(tm.DataFlowDiagrams))
	}

	foundIncludedDfd := false
	for _, dfd := range tm.DataFlowDiagrams {
		if dfd.Name == "included dfd" {
			foundIncludedDfd = true
		}

		if dfd.Name == "shared dfd" {
			if len(dfd.Processes) != 1 || dfd.Processes[0].Name != "parent proc" {
				t.Errorf("The parent's 'shared dfd' should not have been overwritten")
			}
		}
	}

	if !foundIncludedDfd {
		t.Errorf("We didn't find the included-only dfd")
	}

	// Mermaid diagrams: dedup by name, keeping the parent's copy
	if len(tm.MermaidDiagrams) != 2 {
		t.Errorf("Expected 2 mermaid diagrams but got %d", len(tm.MermaidDiagrams))
	}

	foundIncludedMermaid := false
	for _, mermaid := range tm.MermaidDiagrams {
		if mermaid.Name == "included mermaid" {
			foundIncludedMermaid = true
		}

		if mermaid.Name == "shared mermaid" && mermaid.Content != "graph TD; P-->Q;" {
			t.Errorf("The parent's 'shared mermaid' should not have been overwritten")
		}
	}

	if !foundIncludedMermaid {
		t.Errorf("We didn't find the included-only mermaid diagram")
	}
}

func TestTmaddcovIncludeEmptyIncluding(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	tm := &Threatmodel{
		Name:   "no include here",
		Author: "@coverage",
	}

	err := tm.Include(defaultCfg, "./testdata/tm1.hcl")

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "empty including") {
		t.Errorf("We should have an error about an empty including, got: %s", err)
	}
}

func TestTmaddcovIncludeMissingFile(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-missing-include.hcl", false)

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if strings.Contains(err.Error(), "empty including") {
		t.Errorf("We should have a fetch error, not an empty including error, got: %s", err)
	}
}

func TestTmaddcovIncludeInvalidChild(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/tmaddcov-badinclude.hcl", false)

	if err == nil {
		t.Fatalf("We should have gotten an error")
	}

	if !strings.Contains(err.Error(), "author") {
		t.Errorf("We should have an error about the child's missing author, got: %s", err)
	}
}

func TestTmaddcovFetchRemoteTmTempDirFailure(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()

	// Point TMPDIR at a directory that doesn't exist so that
	// fetchRemoteTm's os.MkdirTemp call fails
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "does-not-exist"))

	_, err := fetchRemoteTm(defaultCfg, "tmaddcov-included.hcl", "./testdata/tmaddcov-parent.hcl")

	if err == nil {
		t.Errorf("We should have gotten an error creating the temp dir")
	}
}

package spec

import (
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
	defaultCfg.AllowRemoteImports = true
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
	defaultCfg.AllowRemoteImports = true
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

func TestRemoteImportDisabledByDefault(t *testing.T) {
	defaultCfg := &ThreatmodelSpecConfig{}
	defaultCfg.setDefaults()
	// AllowRemoteImports defaults to false; a remote `including` must be
	// rejected before any network fetch happens.
	tmParser := NewThreatmodelParser(defaultCfg)

	err := tmParser.ParseFile("./testdata/including/corp-app-remote.hcl", false)
	if err == nil {
		t.Fatalf("expected remote import to be rejected when allow_remote_imports is false")
	}

	if !strings.Contains(err.Error(), "allow_remote_imports") {
		t.Errorf("expected error to mention allow_remote_imports, got: %s", err)
	}
}

func TestIsRemoteSource(t *testing.T) {
	cases := []struct {
		src  string
		want bool
	}{
		{"shared/tower.hcl", false},
		{"tower.hcl", false},
		{"file:///etc/passwd", false},
		{"https://example.com/tower.hcl", true},
		{"http://169.254.169.254/latest/meta-data/", true},
		{"git::https://github.com/threatcl/spec.git", true},
		{"github.com/threatcl/spec", true},
	}

	for _, tc := range cases {
		got, err := isRemoteSource(tc.src, "/tmp")
		if err != nil {
			t.Errorf("isRemoteSource(%q) unexpected error: %s", tc.src, err)
			continue
		}
		if got != tc.want {
			t.Errorf("isRemoteSource(%q) = %v, want %v", tc.src, got, tc.want)
		}
	}
}

func TestEnsureLocalSourceContained(t *testing.T) {
	base := "/home/user/models"

	allowed := []string{
		"tower.hcl",
		"shared/tower.hcl",
		"./shared/tower.hcl",
	}
	for _, src := range allowed {
		if err := ensureLocalSourceContained(base, src); err != nil {
			t.Errorf("ensureLocalSourceContained(%q) = %v, want nil", src, err)
		}
	}

	blocked := []string{
		"../../../etc/passwd",
		"file:///etc/passwd",
		"/etc/passwd",
		"shared/../../secrets.hcl",
	}
	for _, src := range blocked {
		if err := ensureLocalSourceContained(base, src); err == nil {
			t.Errorf("ensureLocalSourceContained(%q) = nil, want error", src)
		}
	}
}

func TestEnsureWithin(t *testing.T) {
	base := "/tmp/hcltm123/nest"

	if err := ensureWithin(base, base+"/tower.hcl"); err != nil {
		t.Errorf("ensureWithin in-tree = %v, want nil", err)
	}
	if err := ensureWithin(base, base+"/sub/dir/tower.hcl"); err != nil {
		t.Errorf("ensureWithin nested in-tree = %v, want nil", err)
	}

	// The "repo|../../etc/passwd" traversal form must be rejected.
	if err := ensureWithin(base, base+"/../../../../etc/passwd"); err == nil {
		t.Errorf("ensureWithin traversal = nil, want error")
	}
}

func TestRemoteHost(t *testing.T) {
	cases := []struct {
		detected string
		want     string
	}{
		{"https://github.com/threatcl/spec.git", "github.com"},
		{"git::https://github.com/threatcl/spec.git", "github.com"},
		{"git::ssh://git@github.com/threatcl/spec.git", "github.com"},
		{"git::https://169.254.169.254/x.git", "169.254.169.254"},
		{"git@github.com:threatcl/spec.git", "github.com"},
		{"https://example.com:8443/tower.hcl", "example.com"},
	}

	for _, tc := range cases {
		if got := remoteHost(tc.detected); got != tc.want {
			t.Errorf("remoteHost(%q) = %q, want %q", tc.detected, got, tc.want)
		}
	}
}

func TestAssertRemoteHostAllowed(t *testing.T) {
	// Loopback and link-local hosts must be rejected, even via git.
	blocked := []string{
		"git::https://127.0.0.1/x.git",
		"git::http://169.254.169.254/latest/meta-data/",
		"https://127.0.0.1/tower.hcl",
	}
	for _, src := range blocked {
		if err := assertRemoteHostAllowed(src, "/tmp"); err == nil {
			t.Errorf("assertRemoteHostAllowed(%q) = nil, want error", src)
		}
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

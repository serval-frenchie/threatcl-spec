package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func bumpVersionWriteTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp file: %s", err)
	}
	return path
}

func TestBumpVersionUpdateVersionFile(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		oldVersion string
		newVersion string
		out        string
		errString  string
	}{
		{
			"simple_bump",
			`package spec

var Version = "0.2.1"
`,
			"0.2.1",
			"0.2.2",
			`package spec

var Version = "0.2.2"
`,
			"",
		},
		{
			"preserves_surrounding_content",
			`package spec

// Version is the current spec version
var Version = "0.3.3"

var Other = "0.3.3"
`,
			"0.3.3",
			"0.4.0",
			`package spec

// Version is the current spec version
var Version = "0.4.0"

var Other = "0.3.3"
`,
			"",
		},
		{
			"version_not_found",
			`package spec

var Version = "0.2.2"
`,
			"0.2.1",
			"0.2.3",
			"",
			"no changes made - version 0.2.1 not found",
		},
		{
			"dots_are_not_regex_wildcards",
			`package spec

var Version = "0x2x1"
`,
			"0.2.1",
			"0.2.2",
			"",
			"no changes made - version 0.2.1 not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := bumpVersionWriteTempFile(t, "version.go", tc.in)

			err := updateVersionFile(path, tc.oldVersion, tc.newVersion)

			if tc.errString != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tc.errString)
				}
				if !strings.Contains(err.Error(), tc.errString) {
					t.Errorf("expected error containing '%s', got '%s'", tc.errString, err)
				}

				// The file must be left untouched on error
				got, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("failed to re-read file: %s", readErr)
				}
				if string(got) != tc.in {
					t.Errorf("file was modified despite error, got:\n%s", got)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("failed to re-read file: %s", readErr)
			}
			if string(got) != tc.out {
				t.Errorf("expected:\n%s\ngot:\n%s", tc.out, got)
			}
		})
	}
}

func TestBumpVersionUpdateVersionFileMissingFile(t *testing.T) {
	err := updateVersionFile(filepath.Join(t.TempDir(), "nope.go"), "0.2.1", "0.2.2")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected a not-exist error, got '%s'", err)
	}
}

func TestBumpVersionUpdateVersionFileUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, file permissions are not enforced")
	}

	path := bumpVersionWriteTempFile(t, "version.go", `var Version = "0.2.1"`)
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatalf("failed to chmod temp file: %s", err)
	}

	err := updateVersionFile(path, "0.2.1", "0.2.2")
	if err == nil {
		t.Fatal("expected write error for read-only file, got nil")
	}
	if !os.IsPermission(err) {
		t.Errorf("expected a permission error, got '%s'", err)
	}
}

func TestBumpVersionUpdateTestDataFile(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		oldVersion string
		newVersion string
		out        string
	}{
		{
			"hcl_spec_version",
			`spec_version = "0.2.1"

threatmodel "test" {
  author = "@xntrik"
}
`,
			"0.2.1",
			"0.2.2",
			`spec_version = "0.2.2"

threatmodel "test" {
  author = "@xntrik"
}
`,
		},
		{
			"json_spec_version",
			`{"spec_version": "0.2.1", "threatmodels": []}`,
			"0.2.1",
			"0.2.2",
			`{"spec_version": "0.2.2", "threatmodels": []}`,
		},
		{
			"replaces_all_occurrences",
			`spec_version = "0.2.1"
other = "0.2.1"
`,
			"0.2.1",
			"0.2.2",
			`spec_version = "0.2.2"
other = "0.2.2"
`,
		},
		{
			"unquoted_version_untouched",
			`version 0.2.1 is mentioned but not quoted
`,
			"0.2.1",
			"0.2.2",
			`version 0.2.1 is mentioned but not quoted
`,
		},
		{
			"no_matches_is_noop",
			`spec_version = "0.1.0"
`,
			"0.2.1",
			"0.2.2",
			`spec_version = "0.1.0"
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := bumpVersionWriteTempFile(t, "tm.hcl", tc.in)

			if err := updateTestDataFile(path, tc.oldVersion, tc.newVersion); err != nil {
				t.Fatalf("unexpected error: %s", err)
			}

			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatalf("failed to re-read file: %s", readErr)
			}
			if string(got) != tc.out {
				t.Errorf("expected:\n%s\ngot:\n%s", tc.out, got)
			}
		})
	}
}

func TestBumpVersionUpdateTestDataFileMissingFile(t *testing.T) {
	err := updateTestDataFile(filepath.Join(t.TempDir(), "nope.hcl"), "0.2.1", "0.2.2")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !os.IsNotExist(err) {
		t.Errorf("expected a not-exist error, got '%s'", err)
	}
}

func TestBumpVersionUpdateTestDataFileNoopSkipsWrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, file permissions are not enforced")
	}

	// A read-only file with no matches must not error, because the
	// no-op path returns before attempting to write.
	path := bumpVersionWriteTempFile(t, "tm.hcl", `spec_version = "0.1.0"`)
	if err := os.Chmod(path, 0444); err != nil {
		t.Fatalf("failed to chmod temp file: %s", err)
	}

	if err := updateTestDataFile(path, "0.2.1", "0.2.2"); err != nil {
		t.Errorf("expected no-op to succeed without writing, got '%s'", err)
	}
}

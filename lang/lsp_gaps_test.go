package lang

import (
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
)

// Tests in this file target branch gaps in the LSP-style helpers: nil-input
// guards, hover misses, enum listings, non-literal enum values, cursor
// positions outside any block, and diagnostic ordering edge cases.

// --- hover -------------------------------------------------------------------

func TestHoverAtNilInputs(t *testing.T) {
	pos := hcl.Pos{Line: 1, Column: 1, Byte: 0}
	if h := HoverAt(nil, pos); h != nil {
		t.Errorf("HoverAt(nil file) = %+v, want nil", h)
	}
	if h := HoverAt(&ParsedFile{}, pos); h != nil {
		t.Errorf("HoverAt(file with nil body) = %+v, want nil", h)
	}
}

func TestHoverMisses(t *testing.T) {
	src := "threatmodel \"M\" {\n  author     = \"x\"\n  bogus_attr = \"nope\"\n\n  bogus_block {\n    foo = \"bar\"\n  }\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	tests := []struct {
		name   string
		anchor string
		plus   int
	}{
		{"unknown attribute name", "bogus_attr", 1},
		{"unknown block keyword", "bogus_block", 1},
		{"attribute value is not a symbol", "\"x\"", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if h := HoverAt(pf, cursor(t, src, tc.anchor, tc.plus)); h != nil {
				t.Errorf("expected nil hover, got %+v", h)
			}
		})
	}
}

func TestHoverEnumAttrListsAllowedValues(t *testing.T) {
	src := readFixture(t, "valid.hcl")
	pf, _ := ParseSource("valid.hcl", src)

	// likelihood lives three blocks deep (threatmodel > threat > risk), so this
	// also exercises the nested-body descent.
	h := HoverAt(pf, cursor(t, string(src), "likelihood", 1))
	if h == nil {
		t.Fatal("expected hover on the likelihood attribute")
	}
	for _, want := range []string{"**likelihood**", "required", "Allowed values:", "very_high"} {
		if !strings.Contains(h.Contents, want) {
			t.Errorf("likelihood hover contents missing %q:\n%s", want, h.Contents)
		}
	}
	if got := rangeText(src, h.Range.Ptr()); got != "likelihood" {
		t.Errorf("hover range covers %q, want %q", got, "likelihood")
	}
}

// --- completion ----------------------------------------------------------------

func TestCompletionsAtNilInputs(t *testing.T) {
	pos := hcl.Pos{Line: 1, Column: 1, Byte: 0}
	if got := CompletionsAt(nil, pos); got != nil {
		t.Errorf("CompletionsAt(nil file) = %v, want nil", got)
	}
	if got := CompletionsAt(&ParsedFile{}, pos); got != nil {
		t.Errorf("CompletionsAt(file with nil body) = %v, want nil", got)
	}
}

func TestCompletionValueSlotNonEnumAttr(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n  description = \n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	got := CompletionsAt(pf, cursor(t, src, "description = ", len("description = ")))
	if len(got) != 0 {
		t.Errorf("expected no candidates in a non-enum attribute value slot, got %v", labels(got))
	}
}

func TestCompletionInsideUnknownBlockBody(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n  bogus_block {\n    \n  }\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	got := CompletionsAt(pf, cursor(t, src, "bogus_block {\n", len("bogus_block {\n")+4))
	if len(got) != 0 {
		t.Errorf("expected no candidates inside an unknown block, got %v", labels(got))
	}
}

func TestCompletionUnclosedBlockAtEOF(t *testing.T) {
	// EOF immediately after the open brace: hclsyntax recovers a block whose
	// close-brace range collapses onto the open brace, so the body is treated
	// as extending to the end of the source.
	src := "threatmodel \"M\" {"
	pf, _ := ParseSource("t.hcl", []byte(src))

	got := labels(CompletionsAt(pf, posAt(src, len(src))))
	for _, want := range []string{"author", "threat"} {
		if !contains(got, want) {
			t.Errorf("completion in unclosed threatmodel missing %q; got %v", want, got)
		}
	}
}

func TestCompletionPosBeyondEOF(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	// A stale editor position past the end of the file must not panic and
	// resolves to the root body.
	got := labels(CompletionsAt(pf, posAt(src, len(src)+8)))
	for _, want := range []string{"threatmodel", "spec_version"} {
		if !contains(got, want) {
			t.Errorf("completion beyond EOF missing root candidate %q; got %v", want, got)
		}
	}
}

// --- position helpers ----------------------------------------------------------

func TestLinePrefixClampsOffsets(t *testing.T) {
	src := []byte("a = 1\nbb = 2")
	tests := []struct {
		name    string
		byteOff int
		want    string
	}{
		{"negative offset clamps to start", -3, ""},
		{"offset beyond source clamps to end", len(src) + 10, "bb = 2"},
		{"mid-line offset", 3, "a ="},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := linePrefix(src, tc.byteOff); got != tc.want {
				t.Errorf("linePrefix(%d) = %q, want %q", tc.byteOff, got, tc.want)
			}
		})
	}
}

func TestAttrValueSlotEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		wantName string
		wantOK   bool
	}{
		{"value slot", "  stride = ", "stride", true},
		{"no equals sign", "  stride", "", false},
		{"equals with empty left-hand side", "  = \"x\"", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, ok := attrValueSlot(tc.prefix)
			if name != tc.wantName || ok != tc.wantOK {
				t.Errorf("attrValueSlot(%q) = (%q, %v), want (%q, %v)", tc.prefix, name, ok, tc.wantName, tc.wantOK)
			}
		})
	}
}

// --- diagnostics -----------------------------------------------------------------

func TestDiagnosticsEnumSkipsNonLiteralValues(t *testing.T) {
	// References and non-string literals are not statically resolvable, so the
	// enum layer must skip them rather than flag them (and the structural layer
	// must not evaluate them).
	src := "threatmodel \"M\" {\n" +
		"  author = \"x\"\n" +
		"  threat \"t\" {\n" +
		"    description = \"d\"\n" +
		"    stride      = var.words\n" +
		"    impacts     = [var.word]\n" +
		"    risk {\n" +
		"      likelihood = var.level\n" +
		"      impact     = 5\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	diags := Diagnostics("t.hcl", []byte(src))
	if len(diags) != 0 {
		t.Errorf("expected non-literal enum values to be skipped, got %v", diags)
	}
}

func TestDiagnosticsRiskValueSeparatorsNormalised(t *testing.T) {
	// Risk tokens fold case, spaces, and hyphens to single underscores, so
	// "Very - High" is a valid spelling of very_high.
	src := "threatmodel \"M\" {\n" +
		"  author = \"x\"\n" +
		"  threat \"t\" {\n" +
		"    description = \"d\"\n" +
		"    risk {\n" +
		"      likelihood = \"Very - High\"\n" +
		"      impact     = \" LOW \"\n" +
		"    }\n" +
		"  }\n" +
		"}\n"
	diags := Diagnostics("t.hcl", []byte(src))
	if len(diags) != 0 {
		t.Errorf("expected normalised risk spellings to be accepted, got %v", diags)
	}
}

func TestCanonicalRiskTokenNormalisation(t *testing.T) {
	tests := []struct{ in, want string }{
		{"High", "high"},
		{" very high ", "very_high"},
		{"very - high", "very_high"},
		{"Very--High", "very_high"},
	}
	for _, tc := range tests {
		if got := canonicalRiskToken(tc.in); got != tc.want {
			t.Errorf("canonicalRiskToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDiagBeforeOrdering(t *testing.T) {
	rng := func(file string, byteOff int) *hcl.Range {
		return &hcl.Range{Filename: file, Start: hcl.Pos{Byte: byteOff}}
	}
	diag := func(subject *hcl.Range) *hcl.Diagnostic {
		return &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "x", Subject: subject}
	}

	tests := []struct {
		name string
		a, b *hcl.Diagnostic
		want bool
	}{
		{"both position-less", diag(nil), diag(nil), false},
		{"position-less sorts first", diag(nil), diag(rng("a.hcl", 0)), true},
		{"positioned after position-less", diag(rng("a.hcl", 0)), diag(nil), false},
		{"earlier filename first", diag(rng("a.hcl", 9)), diag(rng("b.hcl", 0)), true},
		{"later filename after", diag(rng("b.hcl", 0)), diag(rng("a.hcl", 9)), false},
		{"same file orders by byte offset", diag(rng("a.hcl", 1)), diag(rng("a.hcl", 2)), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := diagBefore(tc.a, tc.b); got != tc.want {
				t.Errorf("diagBefore = %v, want %v", got, tc.want)
			}
		})
	}
}

// --- symbols -----------------------------------------------------------------------

func TestSymbolsNilInputs(t *testing.T) {
	if got := Symbols(nil); got != nil {
		t.Errorf("Symbols(nil file) = %v, want nil", got)
	}
	if got := Symbols(&ParsedFile{}); got != nil {
		t.Errorf("Symbols(file with nil body) = %v, want nil", got)
	}
}

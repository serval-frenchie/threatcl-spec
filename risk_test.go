package spec

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// parseRawErr parses raw HCL and returns the error (if any) without failing the
// test, for cases that are expected to be rejected during validation.
func parseRawErr(src string) error {
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	return p.ParseHCLRaw([]byte(src))
}

func riskTM(body string) string {
	return `spec_version = "` + Version + `"

threatmodel "Payments API" {
  author = "@security-team"

  threat "token intercept" {
    description = "Session token intercepted in transit"
` + body + `
  }
}
`
}

func TestRiskParseAndNormalize(t *testing.T) {
	// Mixed case + a space, to exercise canonicalisation.
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "High"
      impact     = "Very High"
      rationale  = "Token sent unencrypted over shared segments"
    }`))

	tm := p.GetWrapped().Threatmodels[0]
	if len(tm.Threats) != 1 || tm.Threats[0].Risk == nil {
		t.Fatalf("expected one threat with a risk block")
	}
	r := tm.Threats[0].Risk

	if r.Likelihood != RiskLevelHigh {
		t.Errorf("likelihood = %q, want %q", r.Likelihood, RiskLevelHigh)
	}
	if r.Impact != RiskLevelVeryHigh {
		t.Errorf("impact = %q, want %q", r.Impact, RiskLevelVeryHigh)
	}
	if r.Rationale == "" {
		t.Errorf("rationale was dropped")
	}
	// matrix[high][very_high] = critical
	if got := r.Severity(); got != SeverityCritical {
		t.Errorf("Severity() = %q, want %q", got, SeverityCritical)
	}
}

func TestRiskSeverityMatrix(t *testing.T) {
	cases := []struct {
		likelihood string
		impact     string
		want       string
	}{
		{RiskLevelHigh, RiskLevelHigh, SeverityHigh},
		{RiskLevelVeryHigh, RiskLevelHigh, SeverityCritical},
		{RiskLevelVeryHigh, RiskLevelVeryHigh, SeverityCritical},
		{RiskLevelVeryLow, RiskLevelVeryLow, SeverityInfo},
		{RiskLevelMedium, RiskLevelVeryHigh, SeverityHigh},
		{RiskLevelLow, RiskLevelMedium, SeverityLow},
		{RiskLevelMedium, RiskLevelMedium, SeverityMedium},
	}

	for _, tc := range cases {
		r := &Risk{Likelihood: tc.likelihood, Impact: tc.impact}
		if got := r.Severity(); got != tc.want {
			t.Errorf("Severity(%s, %s) = %q, want %q", tc.likelihood, tc.impact, got, tc.want)
		}
	}
}

func TestRiskSeverityOverride(t *testing.T) {
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "low"
      impact     = "low"
      severity   = "Critical"
    }`))
	r := p.GetWrapped().Threatmodels[0].Threats[0].Risk

	if r.SeverityOverride != SeverityCritical {
		t.Errorf("override = %q, want %q", r.SeverityOverride, SeverityCritical)
	}
	if got := r.Severity(); got != SeverityCritical {
		t.Errorf("Severity() = %q, want override %q", got, SeverityCritical)
	}
}

func TestRiskInherentScore(t *testing.T) {
	cases := []struct {
		likelihood string
		impact     string
		want       float64
	}{
		{RiskLevelMedium, RiskLevelMedium, 25.0},  // 0.5*0.5*100
		{RiskLevelVeryLow, RiskLevelVeryLow, 1.0}, // 0.1*0.1*100
		{RiskLevelHigh, RiskLevelMedium, 37.5},    // 0.75*0.5*100
	}
	for _, tc := range cases {
		r := &Risk{Likelihood: tc.likelihood, Impact: tc.impact}
		if got := r.InherentScore(); got != tc.want {
			t.Errorf("InherentScore(%s, %s) = %v, want %v", tc.likelihood, tc.impact, got, tc.want)
		}
	}
}

func TestRiskResidual(t *testing.T) {
	// inherent medium×medium = 25; one implemented control reduces 80%.
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "medium"
      impact     = "medium"
    }

    control "TLS enforced end to end" {
      implemented    = true
      description    = "tls"
      risk_reduction = 80
    }

    control "Future control" {
      implemented    = false
      description    = "not done yet"
      risk_reduction = 90
    }`))
	tr := p.GetWrapped().Threatmodels[0].Threats[0]

	if got := tr.Risk.InherentScore(); got != 25.0 {
		t.Fatalf("inherent score = %v, want 25", got)
	}
	// only the implemented control counts: 25 * (1-0.8) = 5
	if got := tr.ResidualScore(); got != 5.0 {
		t.Errorf("residual score = %v, want 5", got)
	}
	if got := tr.ResidualRiskReduction(); got != 80.0 {
		t.Errorf("residual reduction = %v, want 80", got)
	}
	if got := tr.ResidualSeverity(); got != SeverityInfo {
		t.Errorf("residual severity = %q, want %q", got, SeverityInfo)
	}
}

func TestRiskResidualDiminishingReturns(t *testing.T) {
	// Two implemented 50% controls => factor 0.25, not 100% (no naive sum).
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "medium"
      impact     = "medium"
    }

    control "A" {
      implemented    = true
      description    = "a"
      risk_reduction = 50
    }

    control "B" {
      implemented    = true
      description    = "b"
      risk_reduction = 50
    }`))
	tr := p.GetWrapped().Threatmodels[0].Threats[0]

	// 25 * 0.5 * 0.5 = 6.25 -> round1 -> 6.3
	if got := tr.ResidualScore(); got != 6.3 {
		t.Errorf("residual score = %v, want 6.3", got)
	}
	if got := tr.ResidualRiskReduction(); got != 75.0 {
		t.Errorf("residual reduction = %v, want 75", got)
	}
}

func TestRiskResidualNoControls(t *testing.T) {
	tr := &Threat{Risk: &Risk{Likelihood: RiskLevelMedium, Impact: RiskLevelMedium}}
	if got := tr.ResidualScore(); got != 25.0 {
		t.Errorf("residual score with no controls = %v, want inherent 25", got)
	}
	if got := tr.ResidualRiskReduction(); got != 0.0 {
		t.Errorf("residual reduction with no controls = %v, want 0", got)
	}
}

func TestRiskInvalidEnum(t *testing.T) {
	err := parseRawErr(riskTM(`    risk {
      likelihood = "extreme"
      impact     = "medium"
    }`))
	if err == nil {
		t.Fatal("expected an error for an invalid likelihood enum")
	}
	if !strings.Contains(err.Error(), "invalid risk likelihood") {
		t.Errorf("error = %q, want it to mention invalid risk likelihood", err)
	}
}

func TestRiskInvalidSeverityOverride(t *testing.T) {
	err := parseRawErr(riskTM(`    risk {
      likelihood = "low"
      impact     = "low"
      severity   = "apocalyptic"
    }`))
	if err == nil {
		t.Fatal("expected an error for an invalid severity override")
	}
	if !strings.Contains(err.Error(), "invalid risk severity") {
		t.Errorf("error = %q, want it to mention invalid risk severity", err)
	}
}

func TestRiskMissingRequiredAttr(t *testing.T) {
	// likelihood is required when the risk block is present.
	err := parseRawErr(riskTM(`    risk {
      impact = "low"
    }`))
	if err == nil {
		t.Fatal("expected an error for a risk block missing likelihood")
	}
}

func TestRiskOptional(t *testing.T) {
	// A threat with no risk block stays valid (backward compatibility).
	p := parseRaw(t, riskTM(``))
	tr := p.GetWrapped().Threatmodels[0].Threats[0]
	if tr.Risk != nil {
		t.Errorf("expected no risk block, got %+v", tr.Risk)
	}
	if got := tr.ResidualSeverity(); got != "" {
		t.Errorf("ResidualSeverity() with no risk = %q, want empty", got)
	}
}

func TestRiskOtmExport(t *testing.T) {
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "high"
      impact     = "medium"
      rationale  = "shared network segments"
    }`))
	tm := p.GetWrapped().Threatmodels[0]

	otmJson, err := tm.RenderOtm()
	if err != nil {
		t.Fatalf("RenderOtm error: %s", err)
	}
	out, err := json.Marshal(otmJson)
	if err != nil {
		t.Fatalf("marshal error: %s", err)
	}
	s := string(out)

	// high -> 75 (likelihood), medium -> 50 (impact)
	for _, want := range []string{
		`"likelihood":75`,
		`"impact":50`,
		`"risk_severity":"high"`,
		`"shared network segments"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("OTM json missing %q:\n%s", want, s)
		}
	}
}

func TestRiskMarkdownRender(t *testing.T) {
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "high"
      impact     = "high"
      rationale  = "unencrypted tokens"
    }

    control "TLS" {
      implemented    = true
      description    = "tls"
      risk_reduction = 80
    }`))
	tm := &p.GetWrapped().Threatmodels[0]

	out, err := tm.RenderMarkdown(TmMDTemplate)
	if err != nil {
		t.Fatalf("RenderMarkdown error: %s", err)
	}
	buf := new(strings.Builder)
	if _, err := io.Copy(buf, out); err != nil {
		t.Fatalf("read error: %s", err)
	}
	rendered := buf.String()

	for _, want := range []string{
		"Inherent Severity **high**",
		"unencrypted tokens",
		"Residual Risk (after implemented controls)",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("markdown missing %q:\n%s", want, rendered)
		}
	}
}

func TestRiskDefaultRiskModel(t *testing.T) {
	m := DefaultRiskModel()
	if m == nil {
		t.Fatal("DefaultRiskModel() returned nil")
	}
	if m != defaultRiskModel {
		t.Error("DefaultRiskModel() should return the built-in model")
	}
	if got := m.Ordinals[RiskLevelVeryHigh]; got != 5 {
		t.Errorf("Ordinals[very_high] = %d, want 5", got)
	}
	if got := m.OtmValues[RiskLevelVeryLow]; got != 10 {
		t.Errorf("OtmValues[very_low] = %d, want 10", got)
	}
	if got := m.Matrix[RiskLevelVeryHigh][RiskLevelVeryHigh]; got != SeverityCritical {
		t.Errorf("Matrix[very_high][very_high] = %q, want %q", got, SeverityCritical)
	}
	if len(m.Thresholds) != 5 {
		t.Errorf("len(Thresholds) = %d, want 5", len(m.Thresholds))
	}
}

func TestRiskScoreUnknownLevels(t *testing.T) {
	cases := []struct {
		name       string
		likelihood string
		impact     string
	}{
		{"unknown likelihood", "bogus", RiskLevelMedium},
		{"unknown impact", RiskLevelMedium, "bogus"},
		{"both unknown", "bogus", "bogus"},
		{"both empty", "", ""},
	}
	for _, tc := range cases {
		if got := defaultRiskModel.score(tc.likelihood, tc.impact); got != 0 {
			t.Errorf("%s: score(%q, %q) = %v, want 0", tc.name, tc.likelihood, tc.impact, got)
		}
	}
}

func TestRiskSeverityUnknownLevels(t *testing.T) {
	// Unknown likelihood misses the matrix entirely.
	if got := defaultRiskModel.severity("bogus", RiskLevelMedium); got != "" {
		t.Errorf("severity(bogus, medium) = %q, want empty", got)
	}
	// Known likelihood but unknown impact misses the row.
	if got := defaultRiskModel.severity(RiskLevelMedium, "bogus"); got != "" {
		t.Errorf("severity(medium, bogus) = %q, want empty", got)
	}
	// Risk.Severity with unknown levels and no override falls through to "".
	r := &Risk{Likelihood: "bogus", Impact: "bogus"}
	if got := r.Severity(); got != "" {
		t.Errorf("Severity() with unknown levels = %q, want empty", got)
	}
	if got := r.InherentScore(); got != 0 {
		t.Errorf("InherentScore() with unknown levels = %v, want 0", got)
	}
}

func TestRiskBandForScore(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{100, SeverityCritical},
		{75, SeverityCritical},
		{74.9, SeverityHigh},
		{50, SeverityHigh},
		{25, SeverityMedium},
		{10, SeverityLow},
		{9.9, SeverityInfo},
		{0, SeverityInfo},
		// Below every threshold: the defensive fallback still yields info.
		{-1, SeverityInfo},
	}
	for _, tc := range cases {
		if got := defaultRiskModel.bandForScore(tc.score); got != tc.want {
			t.Errorf("bandForScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestRiskNilReceiver(t *testing.T) {
	var r *Risk
	if got := r.Severity(); got != "" {
		t.Errorf("nil Risk Severity() = %q, want empty", got)
	}
	if got := r.InherentScore(); got != 0 {
		t.Errorf("nil Risk InherentScore() = %v, want 0", got)
	}
}

func TestRiskResidualScoreNoRiskBlock(t *testing.T) {
	tr := &Threat{}
	if got := tr.ResidualScore(); got != 0 {
		t.Errorf("ResidualScore() with no risk = %v, want 0", got)
	}
	if got := tr.ResidualSeverity(); got != "" {
		t.Errorf("ResidualSeverity() with no risk = %q, want empty", got)
	}
}

func TestRiskResidualFactorEdgeCases(t *testing.T) {
	risk := &Risk{Likelihood: RiskLevelMedium, Impact: RiskLevelMedium} // inherent 25

	t.Run("nil and non-positive controls are skipped", func(t *testing.T) {
		tr := &Threat{
			Risk: risk,
			Controls: []*Control{
				nil,
				{Name: "zero", Implemented: true, RiskReduction: 0},
				{Name: "negative", Implemented: true, RiskReduction: -20},
			},
		}
		if got := tr.ResidualScore(); got != 25.0 {
			t.Errorf("residual score = %v, want inherent 25", got)
		}
		if got := tr.ResidualRiskReduction(); got != 0.0 {
			t.Errorf("residual reduction = %v, want 0", got)
		}
	})

	t.Run("reduction above 100 is clamped", func(t *testing.T) {
		tr := &Threat{
			Risk: risk,
			Controls: []*Control{
				{Name: "over", Implemented: true, RiskReduction: 150},
			},
		}
		if got := tr.ResidualScore(); got != 0.0 {
			t.Errorf("residual score = %v, want 0 (clamped to 100%%)", got)
		}
		if got := tr.ResidualRiskReduction(); got != 100.0 {
			t.Errorf("residual reduction = %v, want 100", got)
		}
	})
}

func TestRiskCanonicalToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Very High", "very_high"},
		{"very-high", "very_high"},
		{"VERY_HIGH", "very_high"},
		{"  medium  ", "medium"},
		// Repeated separators collapse to a single underscore.
		{"very  high", "very_high"},
		{"very - high", "very_high"},
		{"very__high", "very_high"},
		{"very -  - high", "very_high"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := canonicalRiskToken(tc.in); got != tc.want {
			t.Errorf("canonicalRiskToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRiskHCLRoundTrip(t *testing.T) {
	p := parseRaw(t, riskTM(`    risk {
      likelihood = "high"
      impact     = "medium"
      severity   = "critical"
      rationale  = "manual override"
    }`))

	hcl := p.HclString()
	if !strings.Contains(hcl, "risk {") {
		t.Fatalf("round-tripped HCL missing risk block:\n%s", hcl)
	}

	// Re-parse the emitted HCL and confirm the risk survived intact.
	p2 := parseRaw(t, hcl)
	r := p2.GetWrapped().Threatmodels[0].Threats[0].Risk
	if r == nil {
		t.Fatal("risk block lost on round-trip")
	}
	if r.Likelihood != RiskLevelHigh || r.Impact != RiskLevelMedium {
		t.Errorf("levels lost on round-trip: %+v", r)
	}
	if r.SeverityOverride != SeverityCritical {
		t.Errorf("severity override lost on round-trip: %q", r.SeverityOverride)
	}
	if r.Rationale != "manual override" {
		t.Errorf("rationale lost on round-trip: %q", r.Rationale)
	}
}

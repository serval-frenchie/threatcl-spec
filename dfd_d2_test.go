package spec

import (
	"strings"
	"testing"
)

func TestDfdD2ParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	out, err := dfd.GenerateD2(tm.Name, DfdRenderOptions{})
	if err != nil {
		t.Fatalf("Error generating d2: %s", err)
	}

	// D2 supports parallel edges natively — one `a -> b: "label"` per flow.
	if c := strings.Count(out, `-> n_server: "http"`); c != 1 {
		t.Errorf("expected 1 occurrence of `-> n_server: \"http\"`, got %d in:\n%s", c, out)
	}
	if c := strings.Count(out, `-> n_server: "websocket"`); c != 1 {
		t.Errorf("expected 1 occurrence of `-> n_server: \"websocket\"`, got %d in:\n%s", c, out)
	}
}

func TestDfdD2ProtocolStyles(t *testing.T) {
	dfd := protocolFlowsDfdTm()

	const amqpColor = "#E69F00"
	const httpsColor = "#56B4E9"

	cases := []struct {
		name      string
		style     ProtocolStyle
		expect    []string
		notExpect []string
	}{
		{
			name:  "label_default",
			style: ProtocolStyleLabel,
			expect: []string{
				`: "login (https)"`,
				`: "events (amqp)"`,
			},
			notExpect: []string{"style.stroke: \"#", "legend: "},
		},
		{
			name:  "none",
			style: ProtocolStyleNone,
			expect: []string{
				`: "login"`,
				`: "events"`,
			},
			notExpect: []string{"https", "amqp", "legend: "},
		},
		{
			name:  "color",
			style: ProtocolStyleColor,
			expect: []string{
				`: "login" { style.stroke: "` + httpsColor + `" }`,
				`: "events" { style.stroke: "` + amqpColor + `" }`,
				`legend: "Protocols" {`,
				`: "amqp" { style.stroke: "` + amqpColor + `" }`,
				`: "https" { style.stroke: "` + httpsColor + `" }`,
			},
			notExpect: []string{`"login (https)"`},
		},
		{
			name:  "both",
			style: ProtocolStyleBoth,
			expect: []string{
				`: "login (https)" { style.stroke: "` + httpsColor + `" }`,
				`legend: "Protocols" {`,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := dfd.GenerateD2("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateD2: %s", err)
			}
			for _, want := range tc.expect {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q in output:\n%s", want, got)
				}
			}
			for _, unwanted := range tc.notExpect {
				if strings.Contains(got, unwanted) {
					t.Errorf("did not expect %q in output:\n%s", unwanted, got)
				}
			}
		})
	}
}

func TestDfdD2UnknownFlowEndpoints(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		exp  string
	}{
		{
			"unknown_source",
			"ghost_src",
			"known",
			`unknown source node "ghost_src"`,
		},
		{
			"unknown_destination",
			"known",
			"ghost_dst",
			`unknown destination node "ghost_dst"`,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dfd := brokenFlowDfd(tc.from, tc.to)
			out, err := dfd.GenerateD2("tm", DfdRenderOptions{})
			if err == nil {
				t.Fatalf("expected error for unknown flow endpoint, got nil and output:\n%s", out)
			}
			if !strings.Contains(err.Error(), tc.exp) {
				t.Errorf("expected error to contain %q, got: %s", tc.exp, err)
			}
			if out != "" {
				t.Errorf("expected empty output on error, got:\n%s", out)
			}
		})
	}
}

func TestDfdD2UnlabeledFlows(t *testing.T) {
	// Single protocol "https" -> first palette color.
	const httpsColor = "#E69F00"

	cases := []struct {
		name      string
		protocol  string
		style     ProtocolStyle
		expect    []string
		notExpect []string
	}{
		{
			name:      "no_label_no_color",
			protocol:  "",
			style:     ProtocolStyleLabel,
			expect:    []string{"n_a -> n_b\n"},
			notExpect: []string{"n_a -> n_b:", "style.stroke: \"#"},
		},
		{
			name:     "color_without_label",
			protocol: "https",
			style:    ProtocolStyleColor,
			expect: []string{
				`n_a -> n_b: { style.stroke: "` + httpsColor + `" }`,
				`legend: "Protocols" {`,
			},
			notExpect: []string{`"(https)"`},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dfd := unlabeledFlowDfd(tc.protocol)
			got, err := dfd.GenerateD2("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateD2: %s", err)
			}
			for _, want := range tc.expect {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q in output:\n%s", want, got)
				}
			}
			for _, unwanted := range tc.notExpect {
				if strings.Contains(got, unwanted) {
					t.Errorf("did not expect %q in output:\n%s", unwanted, got)
				}
			}
		})
	}
}

func TestDfdD2DuplicateNodesSingleEmit(t *testing.T) {
	dfd := sharedZoneDupDfd()
	out, err := dfd.GenerateD2("tm", DfdRenderOptions{})
	if err != nil {
		t.Fatalf("GenerateD2: %s", err)
	}

	// Nodes declared both inside the trust_zone block and again at the top
	// level must only be emitted once, inside the zone container.
	for _, node := range []string{
		`n_proc_dup: "proc_dup" {`,
		`n_ee_dup: "ee_dup" {`,
		`n_data_dup: "data_dup" {`,
		`n_proc_other: "proc_other" {`,
	} {
		if c := strings.Count(out, node); c != 1 {
			t.Errorf("expected 1 occurrence of %s, got %d in:\n%s", node, c, out)
		}
	}
	if c := strings.Count(out, `z_zone1: "zone1" {`); c != 1 {
		t.Errorf("expected 1 zone1 container, got %d in:\n%s", c, out)
	}
}

func TestDfdD2Generate(t *testing.T) {
	cases := []struct {
		name string
		tm   *Threatmodel
		want []string
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			[]string{"direction: right", "shape: circle", "shape: cylinder", "shape: rectangle", " -> "},
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			[]string{`z_zone1: "zone1"`, "style.stroke: red", "style.stroke-dash: 4"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, adfd := range tc.tm.DataFlowDiagrams {
				out, err := adfd.GenerateD2(tc.tm.Name, DfdRenderOptions{})
				if err != nil {
					t.Fatalf("%s: error generating d2: %s", tc.name, err)
				}
				for _, frag := range tc.want {
					if !strings.Contains(out, frag) {
						t.Errorf("%s: expected output to contain %q, got:\n%s", tc.name, frag, out)
					}
				}
			}
		})
	}
}

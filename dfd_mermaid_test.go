package spec

import (
	"strings"
	"testing"
)

func TestDfdMermaidGenerate(t *testing.T) {
	cases := []struct {
		name string
		tm   *Threatmodel
		want []string
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			[]string{"flowchart LR", `n_proc1(("proc1"))`, `n_data1[("data1")]`, `n_external1{"external1"}`, "-->"},
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			[]string{"flowchart LR", `subgraph z_zone1 ["zone1"]`, `n_proc2(("proc2"))`, "end"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, adfd := range tc.tm.DataFlowDiagrams {
				out, err := adfd.GenerateMermaid(tc.tm.Name, DfdRenderOptions{})
				if err != nil {
					t.Fatalf("%s: error generating mermaid: %s", tc.name, err)
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

func TestDfdMermaidParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	out, err := dfd.GenerateMermaid(tm.Name, DfdRenderOptions{})
	if err != nil {
		t.Fatalf("Error generating mermaid: %s", err)
	}

	// Mermaid renders parallel edges as separate `a -- "label" --> b` lines.
	if c := strings.Count(out, `-- "http" -->`); c != 1 {
		t.Errorf("expected 1 occurrence of `-- \"http\" -->`, got %d in:\n%s", c, out)
	}
	if c := strings.Count(out, `-- "websocket" -->`); c != 1 {
		t.Errorf("expected 1 occurrence of `-- \"websocket\" -->`, got %d in:\n%s", c, out)
	}
}

func TestDfdMermaidProtocolStyles(t *testing.T) {
	dfd := protocolFlowsDfdTm()

	// Alphabetical assignment: amqp -> palette[0], https -> palette[1].
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
				`-- "login (https)" -->`,
				`-- "events (amqp)" -->`,
			},
			notExpect: []string{"linkStyle", "subgraph legend"},
		},
		{
			name:  "none",
			style: ProtocolStyleNone,
			expect: []string{
				`-- "login" -->`,
				`-- "events" -->`,
			},
			notExpect: []string{"https", "amqp", "subgraph legend"},
		},
		{
			name:  "color",
			style: ProtocolStyleColor,
			expect: []string{
				`-- "login" -->`,
				`subgraph legend ["Protocols"]`,
				`-- "amqp" -->`,
				`-- "https" -->`,
				"linkStyle 0 stroke:" + httpsColor,
				"linkStyle 1 stroke:" + amqpColor,
				"linkStyle 2 stroke:" + httpsColor,
			},
			notExpect: []string{`-- "login (https)" -->`},
		},
		{
			name:  "both",
			style: ProtocolStyleBoth,
			expect: []string{
				`-- "login (https)" -->`,
				`subgraph legend ["Protocols"]`,
				"linkStyle 0 stroke:" + httpsColor,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := dfd.GenerateMermaid("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateMermaid: %s", err)
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

func TestDfdMermaidUnknownFlowEndpoint(t *testing.T) {
	tm := &Threatmodel{
		Name: "broken",
		DataFlowDiagrams: []*DataFlowDiagram{{
			Processes: []*DfdProcess{{Name: "p1"}},
			Flows:     []*DfdFlow{{Name: "flow", From: "p1", To: "ghost"}},
		}},
	}
	_, err := tm.DataFlowDiagrams[0].GenerateMermaid(tm.Name, DfdRenderOptions{})
	if err == nil {
		t.Fatal("expected error for unknown flow endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected error to mention the missing node, got: %s", err)
	}
}

func TestDfdMermaidUnknownFlowSource(t *testing.T) {
	dfd := brokenFlowDfd("ghost_src", "known")
	out, err := dfd.GenerateMermaid("tm", DfdRenderOptions{})
	if err == nil {
		t.Fatalf("expected error for unknown flow source, got nil and output:\n%s", out)
	}
	if !strings.Contains(err.Error(), `unknown source node "ghost_src"`) {
		t.Errorf("expected error to mention the missing source node, got: %s", err)
	}
}

func TestDfdMermaidUnlabeledFlows(t *testing.T) {
	cases := []struct {
		name     string
		protocol string
		style    ProtocolStyle
	}{
		{"no_name_no_protocol", "", ProtocolStyleLabel},
		{"protocol_suppressed_by_none", "https", ProtocolStyleNone},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dfd := unlabeledFlowDfd(tc.protocol)
			out, err := dfd.GenerateMermaid("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateMermaid: %s", err)
			}
			if !strings.Contains(out, "  n_a --> n_b\n") {
				t.Errorf("expected bare `n_a --> n_b` edge in output:\n%s", out)
			}
			if strings.Contains(out, `-- "`) {
				t.Errorf("did not expect a labeled edge in output:\n%s", out)
			}
		})
	}
}

func TestDfdMermaidDuplicateNodesSingleEmit(t *testing.T) {
	dfd := sharedZoneDupDfd()
	out, err := dfd.GenerateMermaid("tm", DfdRenderOptions{})
	if err != nil {
		t.Fatalf("GenerateMermaid: %s", err)
	}

	// Nodes declared both inside the trust_zone block and again at the top
	// level must only be emitted once, inside the zone subgraph.
	for _, node := range []string{
		`n_proc_dup(("proc_dup"))`,
		`n_ee_dup{"ee_dup"}`,
		`n_data_dup[("data_dup")]`,
		`n_proc_other(("proc_other"))`,
	} {
		if c := strings.Count(out, node); c != 1 {
			t.Errorf("expected 1 occurrence of %s, got %d in:\n%s", node, c, out)
		}
	}
	if c := strings.Count(out, `subgraph z_zone1 ["zone1"]`); c != 1 {
		t.Errorf("expected 1 zone1 subgraph, got %d in:\n%s", c, out)
	}
}

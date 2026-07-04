package spec

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func dfdTm() *Threatmodel {
	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
				},
			},
		},
	}

	return tm
}

func fullDfdTm() *Threatmodel {

	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
					{
						Name:      "proc2",
						TrustZone: "zone1",
					},
				},
				DataStores: []*DfdData{
					{
						Name: "data1",
					},
					{
						Name:      "data2",
						TrustZone: "zone2",
					},
				},
				ExternalElements: []*DfdExternal{
					{
						Name: "external1",
					},
					{
						Name:      "external2",
						TrustZone: "zone3",
					},
				},
				Flows: []*DfdFlow{
					{
						Name: "flow",
						From: "proc1",
						To:   "data1",
					},
					{
						Name: "flow",
						From: "external1",
						To:   "proc1",
					},
					{
						Name: "flow",
						From: "data1",
						To:   "external1",
					},
				},
			},
		},
	}

	return tm

}

func fullDfdTm2() *Threatmodel {

	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				TrustZones: []*DfdTrustZone{
					{
						Name: "zone1",
						Processes: []*DfdProcess{
							{
								Name:      "proc2",
								TrustZone: "zone1",
							},
							{
								Name: "proc9",
							},
						},
						DataStores: []*DfdData{
							{
								Name: "new_data",
							},
						},
						ExternalElements: []*DfdExternal{
							{
								Name: "ee5",
							},
						},
					},
				},
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
				},
				DataStores: []*DfdData{
					{
						Name: "data1",
					},
					{
						Name:      "data2",
						TrustZone: "zone2",
					},
				},
				ExternalElements: []*DfdExternal{
					{
						Name: "external1",
					},
					{
						Name:      "external2",
						TrustZone: "zone3",
					},
				},
				Flows: []*DfdFlow{
					{
						Name: "flow",
						From: "proc1",
						To:   "data1",
					},
					{
						Name: "flow",
						From: "external1",
						To:   "proc1",
					},
					{
						Name: "flow",
						From: "data1",
						To:   "external1",
					},
				},
			},
		},
	}

	return tm

}

// protocolFlowsDfdTm returns a diagram with two flows sharing a protocol and
// one with a different protocol. Exercises sorted color assignment and the
// legend dedup logic.
func protocolFlowsDfdTm() *DataFlowDiagram {
	return &DataFlowDiagram{
		Name: "proto",
		Processes: []*DfdProcess{
			{Name: "client"},
			{Name: "server"},
			{Name: "worker"},
		},
		Flows: []*DfdFlow{
			{Name: "login", From: "client", To: "server", Protocol: "https"},
			{Name: "events", From: "server", To: "worker", Protocol: "amqp"},
			{Name: "static", From: "client", To: "server", Protocol: "https"},
		},
	}
}

// parallelFlowsDfdTm returns a threatmodel with multiple flow blocks sharing
// the same from→to but distinct names. Used to verify that renderers emit
// parallel edges, one per flow, with each label intact.
func parallelFlowsDfdTm() *Threatmodel {
	return &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Name: "parallel",
				Processes: []*DfdProcess{
					{Name: "client"},
					{Name: "server"},
				},
				Flows: []*DfdFlow{
					{Name: "http", From: "client", To: "server"},
					{Name: "websocket", From: "client", To: "server"},
				},
			},
		},
	}
}

// brokenFlowDfd returns a diagram whose single flow references the given
// endpoints; using an undeclared name for either end exercises the error
// propagation paths of the render entrypoints.
func brokenFlowDfd(from, to string) *DataFlowDiagram {
	return &DataFlowDiagram{
		Name: "broken",
		Processes: []*DfdProcess{
			{Name: "known"},
		},
		Flows: []*DfdFlow{
			{Name: "flow", From: from, To: to},
		},
	}
}

// unlabeledFlowDfd returns a diagram whose single flow has no name, so the
// rendered edge label depends entirely on the protocol and style.
func unlabeledFlowDfd(protocol string) *DataFlowDiagram {
	return &DataFlowDiagram{
		Name: "unlabeled",
		Processes: []*DfdProcess{
			{Name: "a"},
			{Name: "b"},
		},
		Flows: []*DfdFlow{
			{From: "a", To: "b", Protocol: protocol},
		},
	}
}

// sharedZoneDupDfd returns a diagram where each node kind is declared twice
// under the same name (once inside a trust_zone block, once at the top level
// with a trust_zone attribute) and multiple attribute-assigned nodes share a
// zone. Exercises the node dedup branches and the zone-cache-hit branch.
func sharedZoneDupDfd() *DataFlowDiagram {
	return &DataFlowDiagram{
		Name: "dups",
		TrustZones: []*DfdTrustZone{
			{
				Name:             "zone1",
				Processes:        []*DfdProcess{{Name: "proc_dup"}},
				ExternalElements: []*DfdExternal{{Name: "ee_dup"}},
				DataStores:       []*DfdData{{Name: "data_dup"}},
			},
		},
		Processes: []*DfdProcess{
			{Name: "proc_dup", TrustZone: "zone1"},
			{Name: "proc_other", TrustZone: "zone1"},
		},
		ExternalElements: []*DfdExternal{
			{Name: "ee_dup", TrustZone: "zone1"},
		},
		DataStores: []*DfdData{
			{Name: "data_dup", TrustZone: "zone1"},
		},
	}
}

func TestDfdFlowLabelVariants(t *testing.T) {
	cases := []struct {
		name  string
		flow  *DfdFlow
		style ProtocolStyle
		want  string
	}{
		{
			"name_and_protocol",
			&DfdFlow{Name: "login", Protocol: "https"},
			ProtocolStyleLabel,
			"login (https)",
		},
		{
			"name_only",
			&DfdFlow{Name: "login"},
			ProtocolStyleLabel,
			"login",
		},
		{
			"protocol_only",
			&DfdFlow{Protocol: "https"},
			ProtocolStyleLabel,
			"(https)",
		},
		{
			"protocol_suppressed_by_none",
			&DfdFlow{Protocol: "https"},
			ProtocolStyleNone,
			"",
		},
		{
			"protocol_suppressed_by_color",
			&DfdFlow{Protocol: "https"},
			ProtocolStyleColor,
			"",
		},
		{
			"empty_flow",
			&DfdFlow{},
			ProtocolStyleBoth,
			"",
		},
		{
			"whitespace_name_and_protocol",
			&DfdFlow{Name: "   ", Protocol: " https "},
			ProtocolStyleBoth,
			"(https)",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := flowLabel(tc.flow, tc.style); got != tc.want {
				t.Errorf("flowLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDfdDotUnknownFlowEndpoints(t *testing.T) {
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
			out, err := dfd.GenerateDot("tm", DfdRenderOptions{})
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

func TestDfdDotSharedZoneAndDuplicateNodes(t *testing.T) {
	dfd := sharedZoneDupDfd()

	dotSrc, err := dfd.GenerateDot("tm", DfdRenderOptions{})
	if err != nil {
		t.Fatalf("GenerateDot: %s", err)
	}

	// Each duplicated node must be emitted exactly once, and the shared zone
	// must produce a single cluster even though four nodes reference it.
	for _, label := range []string{
		`label="proc_dup"`,
		`label="ee_dup"`,
		`label="data_dup"`,
		`label="proc_other"`,
		`label="zone1"`,
	} {
		if c := strings.Count(dotSrc, label); c != 1 {
			t.Errorf("expected 1 occurrence of %s, got %d in:\n%s", label, c, dotSrc)
		}
	}
}

func TestDfdDotParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	dotSrc, err := dfd.GenerateDot(tm.Name, DfdRenderOptions{})
	if err != nil {
		t.Fatalf("Error generating dot: %s", err)
	}

	// DOT supports parallel edges natively — one edge line per flow, each
	// carrying its own label.
	if c := strings.Count(dotSrc, `label="http"`); c != 1 {
		t.Errorf("expected 1 occurrence of label=\"http\", got %d in:\n%s", c, dotSrc)
	}
	if c := strings.Count(dotSrc, `label="websocket"`); c != 1 {
		t.Errorf("expected 1 occurrence of label=\"websocket\", got %d in:\n%s", c, dotSrc)
	}
}

func TestDfdDotProtocolStyles(t *testing.T) {
	dfd := protocolFlowsDfdTm()

	// Palette assignment is alphabetical on distinct protocols: amqp -> first
	// color (#E69F00), https -> second (#56B4E9).
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
				`label="login (https)"`,
				`label="events (amqp)"`,
				`label="static (https)"`,
			},
			notExpect: []string{amqpColor, httpsColor, `label="Protocols"`},
		},
		{
			name:  "none",
			style: ProtocolStyleNone,
			expect: []string{
				`label="login"`,
				`label="events"`,
				`label="static"`,
			},
			notExpect: []string{"https", "amqp", `label="Protocols"`},
		},
		{
			name:  "color",
			style: ProtocolStyleColor,
			expect: []string{
				`label="login"`,
				amqpColor,
				httpsColor,
				`label="Protocols"`,
				`label="amqp"`,
				`label="https"`,
			},
			notExpect: []string{`label="login (https)"`},
		},
		{
			name:  "both",
			style: ProtocolStyleBoth,
			expect: []string{
				`label="login (https)"`,
				`label="events (amqp)"`,
				amqpColor,
				httpsColor,
				`label="Protocols"`,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := dfd.GenerateDot("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateDot: %s", err)
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

func TestDfdDotGenerate(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			d, err := ioutil.TempDir("", "")
			if err != nil {
				t.Fatalf("Error creating tmp dir: %s", err)
			}
			defer os.RemoveAll(d)

			for _, adfd := range tc.tm.DataFlowDiagrams {

				dot, err := adfd.GenerateDot(tc.tm.Name, DfdRenderOptions{})

				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error rendering png: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shoulnd't have", tc.name)
					} else {
						if !strings.Contains(dot, "graph") {
							t.Errorf("%s: Could not find `graph` in DOT output", tc.name)
						}
					}
				}
			}
		})
	}
}

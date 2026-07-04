package spec

import (
	"fmt"
	"io"
	"os"
	"strings"

	version "github.com/hashicorp/go-version"
)

type hcltmConstraint interface {
	// You can see the format used for verConstraint() here:
	// https://github.com/hashicorp/go-version
	//
	// Examples include:
	// ">= 0.0.1"
	// ">= 0.0.1, < 1.4"

	verConstraint() string
	msg() string
	asOf() string
	tmCheck(tm *Threatmodel) bool
}

type controlStringToBlock struct{}

func (c *controlStringToBlock) asOf() string {
	return "0.1.5"
}
func (c *controlStringToBlock) verConstraint() string {
	return ">= 0.0.1"
}
func (c *controlStringToBlock) msg() string {
	return "Deprecation warning: This threat model has defined `control` strings inside of `threat` blocks. As of v0.1.5 It's recommended that you update these to `expanded_control` blocks, as they may be cause errors in future versions of hcltm."
}
func (c *controlStringToBlock) tmCheck(tm *Threatmodel) bool {

	for _, t := range tm.Threats {
		if t.Control != "" {
			return true
		}
	}
	return false
}

type proposedControlToBlock struct{}

func (c *proposedControlToBlock) asOf() string {
	return "0.1.5"
}
func (c *proposedControlToBlock) verConstraint() string {
	return ">= 0.0.1"
}
func (c *proposedControlToBlock) msg() string {
	return "Deprecation warning: This threat model has defined `proposed_control` block(s) inside of `threat` blocks. As of v0.1.5 It's recommended that you update these to `expanded_control` blocks, as they may be cause errors in future versions of hcltm."
}
func (c *proposedControlToBlock) tmCheck(tm *Threatmodel) bool {

	for _, t := range tm.Threats {
		if len(t.ProposedControls) > 0 {
			return true
		}
	}
	return false
}

type expandedControlToControl struct{}

func (c *expandedControlToControl) asOf() string {
	return "0.1.17"
}
func (c *expandedControlToControl) verConstraint() string {
	return ">= 0.0.1"
}
func (c *expandedControlToControl) msg() string {
	return "Deprecation warning: This threat model has defined `expanded_control` block(s) inside of `threat` blocks. As of v0.1.17 it is recommended that you update these to `control` blocks, as they may cause errors in future versions of hcltm."
}
func (c *expandedControlToControl) tmCheck(tm *Threatmodel) bool {
	for _, t := range tm.Threats {
		if len(t.ExpandedControls) > 0 {
			return true
		}
	}
	return false
}

type multiDfd struct{}

func (c *multiDfd) asOf() string {
	return "0.1.6"
}
func (c *multiDfd) verConstraint() string {
	return ">= 0.0.1"
}
func (c *multiDfd) msg() string {
	return "Deprecation warning: This threat model has a defined `data_flow_diagram` block inside of a `threat` block. As of v0.1.6 it is recommended that you update these to `data_flow_diagram_v2` blocks. In the future, we may retire the old block. The new block requires a `title` label."
}
func (c *multiDfd) tmCheck(tm *Threatmodel) bool {
	for _, d := range tm.DataFlowDiagrams {
		if d.ShiftedFromLegacy {
			return true
		}
	}
	return false
}

// VersionConstraints checks all threat models in tmw against all known
// constraints, and returns the matching warnings joined by newlines. If emit
// is true, warnings are also printed to stdout. New callers should prefer
// VersionConstraintsToWriter and control the output themselves.
func VersionConstraints(tmw *ThreatmodelWrapped, emit bool) (string, error) {
	out := io.Discard
	if emit {
		out = os.Stdout
	}
	return VersionConstraintsToWriter(tmw, out)
}

// VersionConstraintsToWriter checks all threat models in tmw against all
// known constraints, in a fixed order, writing each matching warning to w as
// a newline-terminated line. It returns the same warnings joined by newlines.
func VersionConstraintsToWriter(tmw *ThreatmodelWrapped, w io.Writer) (string, error) {
	hcltmConstraints := []hcltmConstraint{
		&controlStringToBlock{},
		&proposedControlToBlock{},
		&expandedControlToControl{},
		&multiDfd{},
	}

	currVer, err := version.NewVersion(tmw.SpecVersion)
	if err != nil {
		return "", err
	}

	warnings := []string{}
	for _, cval := range hcltmConstraints {
		newConst, err := version.NewConstraint(cval.verConstraint())
		if err != nil {
			return "", err
		}

		if newConst.Check(currVer) {
			for _, tm := range tmw.Threatmodels {
				if cval.tmCheck(&tm) {
					warning := fmt.Sprintf("[threatmodel: %s] %s", tm.Name, cval.msg())
					fmt.Fprintf(w, "%s\n", warning)
					warnings = append(warnings, warning)
				}
			}
		}
	}

	return strings.Join(warnings, "\n"), nil

}

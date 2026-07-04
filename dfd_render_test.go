package spec

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestDfdPngGenerate(t *testing.T) {
	// tm := dfdTm()
	//
	// fulltm := fullDfdTm()

	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
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
				err = adfd.GenerateDfdPng(fmt.Sprintf("%s/out.png", d), tc.tm.Name, DfdRenderOptions{})
			}

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error rendering png: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: an error was thrown when it shoulnd't have", tc.name)
				} else {

					// at this point we should have a legitimate png to
					// test

					f, err := os.Open(fmt.Sprintf("%s/out.png", d))
					if err != nil {
						t.Fatalf("%s: Error opening png: %s", tc.name, err)
					}

					buffer := make([]byte, 512)
					_, err = f.Read(buffer)
					if err != nil {
						t.Fatalf("%s: Error reading png: %s", tc.name, err)
					}

					if http.DetectContentType(buffer) != "image/png" {
						t.Errorf("%s: The output file isn't a png, it's '%s'", tc.name, http.DetectContentType(buffer))
					}
				}
			}

		})
	}
}

func TestDfdSvgGenerate(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
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
				err = adfd.GenerateDfdSvg(fmt.Sprintf("%s/out.svg", d), tc.tm.Name, DfdRenderOptions{})
			}

			if err != nil {
				if !strings.Contains(err.Error(), tc.exp) {
					t.Errorf("%s: Error rendering svg: %s", tc.name, err)
				}
			} else {
				if tc.errorthrown {
					t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
				} else {

					// at this point we should have a legitimate svg to
					// test

					f, err := os.Open(fmt.Sprintf("%s/out.svg", d))
					if err != nil {
						t.Fatalf("%s: Error opening svg: %s", tc.name, err)
					}

					buffer := make([]byte, 512)
					_, err = f.Read(buffer)
					if err != nil {
						t.Fatalf("%s: Error reading svg: %s", tc.name, err)
					}

					contentType := http.DetectContentType(buffer)
					if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "svg") {
						t.Errorf("%s: The output file isn't a svg, it's '%s'", tc.name, contentType)
					}
				}
			}

		})
	}
}

func TestDfdPngGenerateBytes(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
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

			for _, adfd := range tc.tm.DataFlowDiagrams {
				pngBytes, err := adfd.GenerateDfdPngBytes(tc.tm.Name, DfdRenderOptions{})

				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error generating png bytes: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
					} else {
						// Verify the bytes are actually a PNG
						if http.DetectContentType(pngBytes) != "image/png" {
							t.Errorf("%s: The output bytes aren't a png, they're '%s'", tc.name, http.DetectContentType(pngBytes))
						}
					}
				}
			}
		})
	}
}

// TestDfdSvgGenerateBytesMethod mirrors TestDfdPngGenerateBytes but goes
// through the public GenerateDfdSvgBytes entrypoint rather than composing
// generateDfdDot + dotToSvgBytes by hand.
func TestDfdSvgGenerateBytesMethod(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
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
			for _, adfd := range tc.tm.DataFlowDiagrams {
				svgBytes, err := adfd.GenerateDfdSvgBytes(tc.tm.Name, DfdRenderOptions{})

				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error generating svg bytes: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
					} else {
						contentType := http.DetectContentType(svgBytes)
						if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "svg") {
							t.Errorf("%s: The output bytes aren't a svg, they're '%s'", tc.name, contentType)
						}
					}
				}
			}
		})
	}
}

// TestDfdRenderErrorPropagation confirms every render entrypoint surfaces the
// error from GenerateDot when a flow references an undeclared node, and that
// the file-writing variants leave nothing behind.
func TestDfdRenderErrorPropagation(t *testing.T) {
	dfd := brokenFlowDfd("known", "ghost_dst")
	const wantErr = `unknown destination node "ghost_dst"`

	checkErr := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected error for unknown flow endpoint, got nil")
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Errorf("expected error to contain %q, got: %s", wantErr, err)
		}
	}

	t.Run("png_file", func(t *testing.T) {
		out := fmt.Sprintf("%s/out.png", t.TempDir())
		checkErr(t, dfd.GenerateDfdPng(out, "tm", DfdRenderOptions{}))
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("expected no png file to be written, stat err: %v", err)
		}
	})

	t.Run("svg_file", func(t *testing.T) {
		out := fmt.Sprintf("%s/out.svg", t.TempDir())
		checkErr(t, dfd.GenerateDfdSvg(out, "tm", DfdRenderOptions{}))
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("expected no svg file to be written, stat err: %v", err)
		}
	})

	t.Run("png_bytes", func(t *testing.T) {
		b, err := dfd.GenerateDfdPngBytes("tm", DfdRenderOptions{})
		checkErr(t, err)
		if b != nil {
			t.Errorf("expected nil png bytes on error, got %d bytes", len(b))
		}
	})

	t.Run("svg_bytes", func(t *testing.T) {
		b, err := dfd.GenerateDfdSvgBytes("tm", DfdRenderOptions{})
		checkErr(t, err)
		if b != nil {
			t.Errorf("expected nil svg bytes on error, got %d bytes", len(b))
		}
	})
}

// TestDfdDotToFileInvalidDot feeds unparseable DOT straight to the file
// writers so the graphviz-side error branch (as opposed to the GenerateDot
// error branch) is exercised.
func TestDfdDotToFileInvalidDot(t *testing.T) {
	garbage := []byte("this is not dot {{{")

	t.Run("png", func(t *testing.T) {
		out := fmt.Sprintf("%s/out.png", t.TempDir())
		if err := dotToPng(garbage, out); err == nil {
			t.Error("expected error rendering invalid dot to png, got nil")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("expected no png file to be written, stat err: %v", err)
		}
	})

	t.Run("svg", func(t *testing.T) {
		out := fmt.Sprintf("%s/out.svg", t.TempDir())
		if err := dotToSvg(garbage, out); err == nil {
			t.Error("expected error rendering invalid dot to svg, got nil")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Errorf("expected no svg file to be written, stat err: %v", err)
		}
	})
}

func TestDfdSvgGenerateBytes(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_dfd",
			dfdTm(),
			"",
			false,
		},
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

			for _, adfd := range tc.tm.DataFlowDiagrams {
				dot, err := adfd.generateDfdDot(tc.tm.Name, DfdRenderOptions{})
				if err != nil {
					t.Fatalf("Error generating dot: %s", err)
				}

				svgBytes, err := dotToSvgBytes([]byte(dot))
				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error generating svg bytes: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shouldn't have", tc.name)
					} else {
						contentType := http.DetectContentType(svgBytes)
						if !strings.Contains(contentType, "xml") && !strings.Contains(contentType, "svg") {
							t.Errorf("%s: The output bytes aren't a svg, they're '%s'", tc.name, contentType)
						}
					}
				}
			}
		})
	}
}

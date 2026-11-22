package ux

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// FixForwardError enforces the UB-CLI-v2 "Teach, Don't Scold" error invariant.
// Every user-facing non-zero failure MUST supply Summary, RemediationCmd, and WhyOneLiner.
type FixForwardError struct {
	Tool           string   `json:"tool"`
	Code           string   `json:"code"`            // Stable machine code, e.g. "BOMHOUND_COMPLIANCE_GATE_FAILED"
	Summary        string   `json:"summary"`         // Calm 1-line explanation of what paused
	RemediationCmd string   `json:"remediation_cmd"` // Immediate copy-pasteable fix
	WhyOneLiner    string   `json:"why"`             // Single non-blocking educational sentence
	DeepWhy        string   `json:"deep_why,omitempty"`
	References     []string `json:"references,omitempty"` // CWE / legal / docs links
	ExitCode       int      `json:"exit_code"`
}

func (e *FixForwardError) Error() string {
	if e == nil {
		return ""
	}
	return sanitizeSingleLine(e.Summary)
}

// Render writes either machine-readable single-line JSON (--json), calm <=3-line default output,
// or full progressive-disclosure output (--why). All strings are ANSI/control-char sanitized.
func (e *FixForwardError) Render(w io.Writer, asJSON bool, showWhy bool) error {
	if e == nil {
		return nil
	}
	if asJSON {
		sanitized := FixForwardError{
			Tool:           sanitizeSingleLine(e.Tool),
			Code:           sanitizeSingleLine(e.Code),
			Summary:        sanitizeSingleLine(e.Summary),
			RemediationCmd: sanitizeSingleLine(e.RemediationCmd),
			WhyOneLiner:    sanitizeSingleLine(e.WhyOneLiner),
			DeepWhy:        sanitizeTerminalText(e.DeepWhy),
			ExitCode:       e.ExitCode,
		}
		if len(e.References) > 0 {
			sanitized.References = make([]string, len(e.References))
			for i, ref := range e.References {
				sanitized.References[i] = sanitizeSingleLine(ref)
			}
		}
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		return enc.Encode(&sanitized)
	}

	tool := sanitizeSingleLine(e.Tool)
	if tool == "" {
		tool = "bomhound"
	}
	summary := sanitizeSingleLine(e.Summary)
	fix := sanitizeSingleLine(e.RemediationCmd)
	why := sanitizeSingleLine(e.WhyOneLiner)
	deepWhy := strings.TrimSpace(sanitizeTerminalText(e.DeepWhy))

	// Line 1: calm summary
	if _, err := fmt.Fprintf(w, "⚠ %s: %s\n", tool, summary); err != nil {
		return err
	}

	// Line 2: immediate copy-pasteable fix
	if fix != "" {
		if _, err := fmt.Fprintf(w, "  Fix:  %s\n", fix); err != nil {
			return err
		}
	}

	// Line 3: educational 1-liner (plus inline --why hint when DeepWhy is available and !showWhy)
	if why != "" || (!showWhy && deepWhy != "") {
		whyLine := why
		if !showWhy && deepWhy != "" {
			codeArg := sanitizeSingleLine(strings.ToLower(e.Code))
			hint := fmt.Sprintf("re-run with --why or `%s explain %s` for details", tool, codeArg)
			if codeArg == "" {
				hint = "re-run with --why for details"
			}
			if whyLine != "" {
				whyLine = fmt.Sprintf("%s (%s)", whyLine, hint)
			} else {
				whyLine = fmt.Sprintf("Run `%s explain %s` (or re-run with --why) for details.", tool, codeArg)
			}
		}
		if _, err := fmt.Fprintf(w, "  Why:  %s\n", whyLine); err != nil {
			return err
		}
	}

	// Progressive disclosure block when --why is requested
	if showWhy && deepWhy != "" {
		if _, err := fmt.Fprintf(w, "\n  Deep Dive (--why):\n  %s\n", strings.ReplaceAll(deepWhy, "\n", "\n  ")); err != nil {
			return err
		}
		for _, ref := range e.References {
			cleanRef := sanitizeSingleLine(ref)
			if cleanRef != "" {
				if _, err := fmt.Fprintf(w, "  Ref:  %s\n", cleanRef); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// EnrichmentSummary captures aggregate license and copyright enrichment counts
// for rendering a calm <=3-line UB-CLI-v2 summary.
type EnrichmentSummary struct {
	FilesProcessed int
	Found          int
	Missing        int
	OutputTarget   string
}

// FormatEnrichmentSummary renders a calm <=3-line UB-CLI-v2 summary of CycloneDX
// license and copyright enrichment results. When showWhy is true, it appends a
// concise Apache-2.0 §4c / 17 U.S.C. §1202 progressive disclosure block.
func FormatEnrichmentSummary(s EnrichmentSummary, showWhy bool) string {
	total := s.Found + s.Missing
	rate := 100.0
	if total > 0 {
		rate = float64(s.Found) / float64(total) * 100.0
	}
	files := s.FilesProcessed
	if files <= 0 {
		files = 1
	}

	icon := "✓"
	if s.Missing > 0 {
		icon = "⚠"
	}

	cleanTarget := sanitizeSingleLine(s.OutputTarget)
	var b strings.Builder

	// Line 1: calm summary
	fmt.Fprintf(&b, "%s bomhound: enriched %d/%d components (%.1f%% copyright coverage) across %d SBOM(s)\n",
		icon, s.Found, total, rate, files)

	// Line 2: immediate next step or output path
	if s.Missing > 0 {
		fmt.Fprintf(&b, "  Next: bomhound explain attribution --why (review %d component(s) missing copyright notices)\n", s.Missing)
	} else if cleanTarget != "" {
		fmt.Fprintf(&b, "  Out:  %s\n", cleanTarget)
	} else {
		fmt.Fprintf(&b, "  Next: bomhound explain cyclonedx --why\n")
	}

	// Line 3: educational 1-liner
	if showWhy {
		fmt.Fprintf(&b, "  Why:  Preserves upstream copyright notices in CycloneDX Evidence.Copyright for Apache-2.0 §4c and 17 U.S.C. §1202 compliance.\n")
		fmt.Fprintf(&b, "\n  Deep Dive (--why):\n")
		fmt.Fprintf(&b, "  Apache-2.0 Section 4(c) requires retaining upstream copyright, patent, trademark, and attribution notices in derivative distributions.\n")
		fmt.Fprintf(&b, "  17 U.S.C. §1202 prohibits stripping Copyright Management Information (CMI) when redistributing third-party code.\n")
		fmt.Fprintf(&b, "  Ref:  https://www.apache.org/licenses/LICENSE-2.0#redistribution\n")
		fmt.Fprintf(&b, "  Ref:  https://www.law.cornell.edu/uscode/text/17/1202\n")
	} else {
		fmt.Fprintf(&b, "  Why:  Preserves upstream attribution required by Apache-2.0 §4c & 17 U.S.C. §1202 (run `bomhound explain attribution --why`).\n")
	}

	return b.String()
}

// remediationTokenRe strictly permits safe canonical package/path identifiers.
var remediationTokenRe = regexp.MustCompile(`^[a-zA-Z0-9@._/-]+$`)

// ValidateRemediationToken enforces strict allowlist quoting for tokens interpolated
// into FixForwardError.RemediationCmd so untrusted input can never smuggle shell metacharacters,
// flags, path traversal, or Unicode homoglyphs into copy-pasteable commands.
func ValidateRemediationToken(token string) bool {
	if token == "" || len(token) > 214 {
		return false
	}
	if !remediationTokenRe.MatchString(token) {
		return false
	}
	if strings.HasPrefix(token, "-") || strings.HasPrefix(token, "/") || strings.HasSuffix(token, "/") {
		return false
	}
	if strings.Contains(token, "..") || strings.Contains(token, "//") {
		return false
	}
	return true
}

// SanitizeTerminalText strips ESC, CSI, OSC, DCS/PM/APC, C0/C1 control characters, DEL,
// and Unicode bidi override characters to prevent terminal injection and clipboard hijacking.
func SanitizeTerminalText(s string) string {
	return sanitizeTerminalText(s)
}

func sanitizeSingleLine(s string) string {
	clean := sanitizeTerminalText(s)
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

// sanitizeTerminalText strips ESC, CSI, OSC, DCS/SOS/PM/APC, and C0/C1 control characters.
func sanitizeTerminalText(s string) string {
	runes := []rune(s)
	var b strings.Builder
	b.Grow(len(s))

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		// Handle ESC (0x1B) sequences
		if r == 0x1b {
			if i+1 >= len(runes) {
				break
			}
			next := runes[i+1]
			switch next {
			case '[': // CSI sequence: ESC [ <params 0x30-0x3F>* <interm 0x20-0x2F>* <final 0x40-0x7E>
				i += 2
				for i < len(runes) {
					c := runes[i]
					if c >= 0x40 && c <= 0x7e {
						break
					}
					i++
				}
			case ']', 'P', 'X', '^', '_': // OSC / DCS / SOS / PM / APC terminated by BEL or ST
				i += 2
				for i < len(runes) {
					if runes[i] == 0x07 || runes[i] == 0x9c {
						break
					}
					if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
						i++
						break
					}
					i++
				}
			default:
				// 2-byte or intermediate ESC sequence
				i++
				for i < len(runes) && runes[i] >= 0x20 && runes[i] <= 0x2f {
					i++
				}
			}
			continue
		}

		// Handle 8-bit C1 CSI (0x9B)
		if r == 0x9b {
			i++
			for i < len(runes) {
				c := runes[i]
				if c >= 0x40 && c <= 0x7e {
					break
				}
				i++
			}
			continue
		}

		// Handle 8-bit C1 OSC/DCS/SOS/PM/APC (0x9D, 0x90, 0x98, 0x9E, 0x9F)
		if r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f {
			i++
			for i < len(runes) {
				if runes[i] == 0x07 || runes[i] == 0x9c {
					break
				}
				if runes[i] == 0x1b && i+1 < len(runes) && runes[i+1] == '\\' {
					i++
					break
				}
				i++
			}
			continue
		}

		// Strip remaining C0 (except \n and \t), DEL (0x7f), C1 (0x80-0x9f), and bidi overrides
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			continue
		}
		if (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			continue
		}

		b.WriteRune(r)
	}

	return b.String()
}

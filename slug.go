package spec

import (
	"strings"
	"unicode"
)

// Slugify converts a free-form element name into its canonical identifier-safe
// slug: lowercase alphanumerics separated by single hyphens, with a divider
// inserted at case boundaries, so "Web App!" and "WebApp" both become
// "web-app". This is the same slugification the OTM exporter uses for element
// ids. Reference resolution treats the two divider forms as equivalent, so a
// quoted reference may use either this kebab form or the underscore form.
func Slugify(s string) string {
	return slugifyWith(s, '-')
}

// SlugifyUnderscore is Slugify with underscores instead of hyphens. This is
// the divider used for dot-notation reference namespaces (process.web_app) —
// underscores rather than hyphens, because a hyphen inside a bare HCL
// expression is easily confused with subtraction — and for OTM attribute keys.
// It matches the threatmodel id derivation convention.
func SlugifyUnderscore(s string) string {
	return slugifyWith(s, '_')
}

func slugifyWith(s string, divider rune) string {
	var slug strings.Builder
	var prevDash bool // Track whether the previous character was a divider to avoid consecutive dividers

	for i, r := range s {
		// Check if the character is alphanumeric (letter or number)
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			// Convert uppercase to lowercase and add a divider if this is not the start and the previous character wasn't a divider
			if unicode.IsUpper(r) && i > 0 && !prevDash {
				slug.WriteRune(divider)
				prevDash = true
			}
			slug.WriteRune(unicode.ToLower(r))
			prevDash = false // Reset the divider tracker
		} else if i > 0 && !prevDash && slug.Len() > 0 { // For non-alphanumeric characters, potentially add a divider if one hasn't been added
			slug.WriteRune(divider)
			prevDash = true // Mark that a divider was added
			continue
		}
	}

	// Remove trailing divider if present
	slugStr := slug.String()
	if strings.HasSuffix(slugStr, string(divider)) {
		slugStr = slugStr[:len(slugStr)-1]
	}

	return slugStr
}

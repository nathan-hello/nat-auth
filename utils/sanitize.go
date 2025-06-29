package utils

import "strings"

func SanitizeInput(input string) string {
	// Remove HTML tags and special characters
	input = strings.TrimSpace(input)
	input = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1 // Remove control characters
		}
		return r
	}, input)
	return input
}

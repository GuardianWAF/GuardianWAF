package tls

// buildAIAURLManual manually constructs the tagged URL bytes for AIA
// (context-specific tag 6 for uniformResourceIdentifier).
// This function is required by tls_extra_test.go.
func buildAIAURLManual(url string) []byte {
	urlBytes := []byte(url)
	result := make([]byte, 0, 2+len(urlBytes))
	result = append(result, 0x86) // tag: context-specific primitive, tag number 6
	result = append(result, byte(len(urlBytes)))
	result = append(result, urlBytes...)
	return result
}

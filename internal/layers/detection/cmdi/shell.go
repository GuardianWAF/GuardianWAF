package cmdi

// shellMetacharacters defines shell metacharacters that serve as injection points.
// Each has a description and risk level for documentation purposes.
var shellMetacharacters = []struct {
	Char        string
	Description string
}{
	{";", "Command separator"},
	{"|", "Pipe operator"},
	{"`", "Backtick command substitution"},
	{"$(", "Dollar-paren command substitution"},
	{"&&", "AND operator"},
	{"||", "OR operator"},
	{">", "Output redirection"},
	{">>", "Append redirection"},
	{"%0a", "URL-encoded newline (LF)"},
	{"%0d", "URL-encoded carriage return (CR)"},
	{"\n", "Newline character"},
	{"\r", "Carriage return character"},
}

// HasShellMetachar returns true if the input contains any shell metacharacter.
func HasShellMetachar(input string) bool {
	for _, m := range shellMetacharacters {
		if len(m.Char) <= len(input) {
			for i := 0; i <= len(input)-len(m.Char); i++ {
				if input[i:i+len(m.Char)] == m.Char {
					return true
				}
			}
		}
	}
	return false
}

// ShellMetacharList returns the list of known shell metacharacters.
func ShellMetacharList() []string {
	result := make([]string, len(shellMetacharacters))
	for i, m := range shellMetacharacters {
		result[i] = m.Char
	}
	return result
}

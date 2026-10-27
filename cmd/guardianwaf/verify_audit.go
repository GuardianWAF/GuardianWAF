package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/guardianwaf/guardianwaf/internal/dashboard"
)

// cmdVerifyAudit checks the hash chain of a persisted dashboard audit log
// (dashboard.audit_path) and prints its head. Exit status 1 means the file
// is unreadable, malformed or has been modified.
func cmdVerifyAudit(args []string) int {
	fs := flag.NewFlagSet("verify-audit", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: guardianwaf verify-audit <audit.jsonl>")
		fmt.Fprintln(fs.Output(), "\nVerifies the dashboard audit log hash chain and prints its head.")
		fmt.Fprintln(fs.Output(), "Compare the head with a copy recorded off the host to detect truncation.")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	head, err := dashboard.VerifyAuditFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit log verification FAILED: %v\n", err)
		return 1
	}
	if head.Seq == 0 {
		fmt.Println("audit log OK: no hash-chained entries")
		return 0
	}
	fmt.Printf("audit log OK: seq=%d hash=%s\n", head.Seq, head.Hash)
	return 0
}

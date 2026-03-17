// Package main provides a simple backend server for testing GuardianWAF.
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from backend! Path: %s\n", r.URL.Path)
	})

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	fmt.Println("Backend server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

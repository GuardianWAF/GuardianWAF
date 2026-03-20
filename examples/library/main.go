// Package main demonstrates using GuardianWAF as a library in a Go application.
//
// Run:
//
//	go run ./examples/library
package main

import (
	"fmt"
	"net/http"

	"github.com/guardianwaf/guardianwaf"
)

func main() {
	waf, err := guardianwaf.New(guardianwaf.Config{
		Mode: guardianwaf.ModeEnforce,
		Threshold: guardianwaf.ThresholdConfig{
			Block: 50,
			Log:   25,
		},
	})
	if err != nil {
		panic(err)
	}
	defer waf.Close()

	// Register event callback
	waf.OnEvent(func(event guardianwaf.Event) {
		if event.Action.String() == "block" {
			fmt.Printf("[BLOCKED] %s %s from %s (score: %d)\n",
				event.Method, event.Path, event.ClientIP, event.Score)
		}
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, protected world!")
	})
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"users": [{"id": 1, "name": "Alice"}]}`)
	})

	fmt.Println("Server starting on :8088 (protected by GuardianWAF)")
	if err := http.ListenAndServe(":8088", waf.Middleware(mux)); err != nil {
		panic(err)
	}
}

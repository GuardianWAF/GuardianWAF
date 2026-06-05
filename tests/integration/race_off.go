//go:build !race

package integration

// underRace is false in normal (non -race) builds; latency-threshold assertions
// are meaningful and enforced.
const underRace = false

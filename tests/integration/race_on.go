//go:build race

package integration

// underRace is true when the binary is built with the race detector (-race).
// The race detector adds large, highly variable timing overhead, so wall-clock
// latency-threshold assertions are meaningless under it and must be skipped.
const underRace = true

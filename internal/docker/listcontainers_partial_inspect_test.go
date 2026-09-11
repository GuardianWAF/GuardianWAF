package docker

import (
	"testing"
)

// Regression (bug-hunt round 31): ListContainers batch-ran `docker inspect
// id1..idN` through dockerCmd, which used exec.Cmd.Output() — stdout was
// discarded when the command exited non-zero. `docker inspect` exits 1
// (while still printing valid inspect JSON for the survivors) when one of
// the IDs is destroyed between `docker ps` and `docker inspect` — the churn
// window this package's event stream exists around. Watcher.sync then failed
// the whole sync, and in event mode there is no periodic retry while the
// stream is alive, so a container started during churn stayed undiscovered
// until an unrelated event arrived.
//
// The fix captures stdout separately from the exit error and recovers the
// survivors: a partial inspect must yield the surviving containers, not a
// failed sync. Deterministic via the fake-CLI seam (builtins only — PATH is
// replaced entirely by t.Setenv).

func TestListContainers_RecoversSurvivorsFromPartialInspect(t *testing.T) {
	dir := writeFakeDocker(t, `#!/bin/sh
if [ "$1" = "--host" ]; then
	shift
	shift
fi
cmd="$1"
shift
case "$cmd" in
	ps)
		printf '%s\n' '{"ID":"abc123def4567890aaaaaaaaaaaaaaaa"}'
		printf '%s\n' '{"ID":"def4567890123456bbbbbbbbbbbbbbbb"}'
		;;
	inspect)
		# Real docker CLI behavior on a missing ID: survivors to stdout,
		# error to stderr, exit 1.
		printf '%s' '[{"Id":"abc123def4567890aaaaaaaaaaaaaaaa","Name":"/web1","Config":{"Labels":{"gwaf.enable":"true","gwaf.host":"web.example.com"}},"State":{"Status":"running"},"NetworkSettings":{"Networks":{"bridge":{"IPAddress":"172.17.0.2","Gateway":"172.17.0.1","NetworkID":"net1"}}}}]'
		echo "Error response from daemon: No such container: def4567890123456bbbbbbbbbbbbbbbb" >&2
		exit 1
		;;
	*)
		echo "unexpected docker subcommand: $cmd" >&2
		exit 1
		;;
esac
`)
	t.Setenv("PATH", dir)

	c := NewClient("")
	containers, err := c.ListContainers("gwaf")
	if err != nil {
		t.Fatalf("FAIL: ListContainers failed on a partial inspect (%v) — surviving containers must be recovered, not discarded", err)
	}
	if len(containers) != 1 {
		t.Fatalf("expected the 1 surviving container, got %d", len(containers))
	}
	if containers[0].ID != "abc123def4567890aaaaaaaaaaaaaaaa" {
		t.Fatalf("survivor mismatch: %q", containers[0].ID)
	}
	if ip := containers[0].NetworkSettings.Networks["bridge"].IPAddress; ip != "172.17.0.2" {
		t.Fatalf("survivor network data missing: %q", ip)
	}
}

#!/usr/bin/env bash
# Report statistically significant >=10% benchmark regressions in benchstat
# output (file argument or stdin) and exit 1 if any are found.
#
# benchstat prints one table per unit. A significant change carries a p-value,
# e.g. "+27.11% (p=0.003 n=8)"; "~" means no significant change and geomean
# rows carry no significance test. Higher sec/op, B/op and allocs/op are
# regressions; for throughput (B/s) a *lower* value is the regression.
set -euo pipefail

awk '
/^pkg:/ { pkg = $2 }
/│/ {
	if ($0 ~ /B\/s/) unit = "throughput"
	else if ($0 ~ /sec\/op|B\/op|allocs\/op/) unit = "cost"
}
/% \(p=/ && !/^geomean/ {
	if (match($0, /[+-][0-9]+(\.[0-9]+)?% \(p=/)) {
		delta = substr($0, RSTART, RLENGTH)
		sign = substr(delta, 1, 1)
		pct = substr(delta, 2) + 0
		if (pct >= 10 && ((unit == "cost" && sign == "+") || (unit == "throughput" && sign == "-"))) {
			printf "%s: %s\n", pkg, $0
			found = 1
		}
	}
}
END { exit found ? 1 : 0 }
' "${1:-/dev/stdin}"

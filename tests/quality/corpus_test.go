package quality

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/guardianwaf/guardianwaf/internal/engine"
)

type corpus struct {
	name       string
	placements []string
	samples    []string
}

func readCorpus(t testing.TB, path string, defaultPlacements ...string) corpus {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := corpus{name: strings.TrimSuffix(filepath.Base(path), ".txt")}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if p, ok := strings.CutPrefix(line, "# placement:"); ok {
			for _, pl := range strings.Split(p, ",") {
				c.placements = append(c.placements, strings.TrimSpace(pl))
			}
			continue
		}
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		c.samples = append(c.samples, line)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(c.placements) == 0 {
		c.placements = defaultPlacements
	}
	if len(c.placements) == 0 {
		t.Fatalf("%s: missing '# placement:' header", path)
	}
	for _, p := range c.placements {
		if placements[p] == nil {
			t.Fatalf("%s: unknown placement %q", path, p)
		}
	}
	return c
}

type outcome struct {
	requests, blocked int
	examples          []string
}

// run sends every sample in every placement. examples collects requests whose
// outcome is the interesting one: blocked benign or unblocked attack samples.
func run(t testing.TB, eng *engine.Engine, c corpus, seq *int, attack bool) outcome {
	var o outcome
	for _, s := range c.samples {
		for _, p := range c.placements {
			*seq++
			r := placements[p](s)
			browserHeaders(r, *seq)
			ev := eng.Check(r)
			o.requests++
			isBlock := ev.Action == engine.ActionBlock
			if isBlock {
				o.blocked++
			}
			if isBlock != attack {
				if len(o.examples) < 60 {
					var dets []string
					for _, f := range ev.Findings {
						dets = append(dets, fmt.Sprintf("%s:%d", f.DetectorName, f.Score))
					}
					o.examples = append(o.examples, fmt.Sprintf("[%s score=%d %s] %q", p, ev.Score, strings.Join(dets, ","), s))
				}
			}
		}
	}
	return o
}

func corpusFiles(t testing.TB, dir string) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in %s (err=%v)", dir, err)
	}
	sort.Strings(files)
	return files
}

// Block-level false-positive budgets on realistic benign traffic.
const (
	maxGeneralFPRate   = 0.01 // user content, search, forms, API bodies
	maxTechnicalFPRate = 0.05 // developer content that legitimately quotes code
	minAttackBlockRate = 0.85 // attacks must still be blocked end to end
)

func TestBenignCorpusFalsePositives(t *testing.T) {
	eng := newPipeline(t)
	root := filepath.Join("..", "..", "testdata", "quality")
	seq := 0
	var total, blocked, techTotal, techBlocked int
	for _, path := range corpusFiles(t, filepath.Join(root, "benign")) {
		c := readCorpus(t, path)
		o := run(t, eng, c, &seq, false)
		rate := float64(o.blocked) / float64(o.requests)
		t.Logf("benign %-22s %5d requests  %4d blocked  %5.2f%%", c.name, o.requests, o.blocked, rate*100)
		for _, ex := range o.examples {
			t.Logf("    FP %s", ex)
		}
		if strings.HasPrefix(c.name, "technical") {
			techTotal += o.requests
			techBlocked += o.blocked
		} else {
			total += o.requests
			blocked += o.blocked
		}
	}
	general := float64(blocked) / float64(total)
	technical := float64(techBlocked) / float64(max(techTotal, 1))
	t.Logf("general benign: %d/%d blocked (%.2f%%); technical: %d/%d (%.2f%%)", blocked, total, general*100, techBlocked, techTotal, technical*100)
	if general > maxGeneralFPRate {
		t.Errorf("general benign block rate %.2f%% exceeds %.0f%% budget", general*100, maxGeneralFPRate*100)
	}
	if technical > maxTechnicalFPRate {
		t.Errorf("technical benign block rate %.2f%% exceeds %.0f%% budget", technical*100, maxTechnicalFPRate*100)
	}
}

func TestAttackCorpusBlockedEndToEnd(t *testing.T) {
	eng := newPipeline(t)
	seq := 0
	var total, blocked int
	for _, path := range corpusFiles(t, filepath.Join("..", "..", "testdata", "attacks")) {
		name := strings.TrimSuffix(filepath.Base(path), ".txt")
		pl := attackPlacements[name]
		if pl == nil {
			pl = []string{"query", "form", "multipart"}
		}
		c := readCorpus(t, path, pl...)
		o := run(t, eng, c, &seq, true)
		rate := float64(o.blocked) / float64(o.requests)
		t.Logf("attack %-22s %5d requests  %4d blocked  %5.2f%%", c.name, o.requests, o.blocked, rate*100)
		for _, ex := range o.examples {
			t.Logf("    MISS %s", ex)
		}
		total += o.requests
		blocked += o.blocked
		if rate < minAttackBlockRate {
			t.Errorf("%s: block rate %.1f%% below %.0f%%", c.name, rate*100, minAttackBlockRate*100)
		}
	}
	t.Logf("attacks: %d/%d blocked (%.2f%%)", blocked, total, float64(blocked)/float64(total)*100)
}

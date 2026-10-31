import { describe, expect, it } from 'vitest'

// The theme is driven by CSS variables (bg-card, text-muted-foreground, ...).
// Hard-coded light palette classes ignore it and show up as white boxes in dark
// mode, so they are not allowed outside the allow-list below.
const FORBIDDEN = /\b(?:bg|border|divide|ring)-(?:gray|slate|zinc|neutral|stone)-(?:50|100|200|300)\b|\btext-(?:gray|slate|zinc|neutral|stone)-\d{3}\b|\bbg-white\b(?!\/)/

// Files that intentionally keep a fixed palette.
const ALLOWED_FILES = new Set([
  // Always-dark topology canvas.
  '../components/routing/routing-graph.tsx',
])
// Fixed-colour widgets: toggle knobs are white in both themes.
const ALLOWED_LINES = [/rounded-full bg-white/]

const sources = import.meta.glob(['../**/*.{ts,tsx}', '!../**/*.test.{ts,tsx}', '!../test/**'], {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>

describe('theme tokens', () => {
  it('scans the source tree', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(20)
  })

  it('uses theme tokens instead of fixed light palette classes', () => {
    const offenders: string[] = []
    for (const [file, text] of Object.entries(sources)) {
      if (ALLOWED_FILES.has(file)) continue
      text.split('\n').forEach((line, i) => {
        if (FORBIDDEN.test(line) && !ALLOWED_LINES.some((re) => re.test(line))) {
          offenders.push(`${file}:${i + 1}: ${line.trim().slice(0, 100)}`)
        }
      })
    }
    expect(offenders).toEqual([])
  })
})

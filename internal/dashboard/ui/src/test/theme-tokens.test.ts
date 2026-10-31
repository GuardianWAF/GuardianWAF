import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// The theme is driven by CSS variables (bg-card, text-muted-foreground, ...).
// Hard-coded light palette classes ignore it and show up as white boxes in dark
// mode, so they are not allowed outside the allow-list below.
const FORBIDDEN = /\b(?:bg|border|divide|ring)-(?:gray|slate|zinc|neutral|stone)-(?:50|100|200|300)\b|\btext-(?:gray|slate|zinc|neutral|stone)-\d{3}\b|\bbg-white\b(?!\/)/

// Files that intentionally keep a fixed palette.
const ALLOWED_FILES = new Set([
  // Always-dark topology canvas.
  'components/routing/routing-graph.tsx',
])
// Fixed-colour widgets: toggle knobs are white in both themes.
const ALLOWED_LINES = [/rounded-full bg-white/]

function sourceFiles(dir: string, base = dir): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) return sourceFiles(path, base)
    if (!/\.tsx?$/.test(name) || /\.test\.tsx?$/.test(name)) return []
    return [path.slice(base.length + 1)]
  })
}

describe('theme tokens', () => {
  it('uses theme tokens instead of fixed light palette classes', () => {
    const root = join(__dirname, '..')
    const offenders: string[] = []
    for (const file of sourceFiles(root)) {
      if (ALLOWED_FILES.has(file)) continue
      readFileSync(join(root, file), 'utf8')
        .split('\n')
        .forEach((line, i) => {
          if (FORBIDDEN.test(line) && !ALLOWED_LINES.some((re) => re.test(line))) {
            offenders.push(`${file}:${i + 1}: ${line.trim().slice(0, 100)}`)
          }
        })
    }
    expect(offenders).toEqual([])
  })
})

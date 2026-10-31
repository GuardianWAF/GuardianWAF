import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { Sidebar } from './sidebar'

function renderSidebar() {
  return render(
    <MemoryRouter>
      <Sidebar mobileOpen={false} onMobileClose={vi.fn()} />
    </MemoryRouter>,
  )
}

describe('Sidebar', () => {
  beforeAll(() => {
    // jsdom has no matchMedia; the sidebar reads it to detect the mobile layout.
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: (query: string) => ({
        matches: false,
        media: query,
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
      }),
    })
  })

  it('groups pages under headings', () => {
    renderSidebar()
    for (const heading of ['Monitor', 'Protect', 'Integrations', 'Scale']) {
      expect(screen.getByText(heading)).toBeInTheDocument()
    }
  })

  it('keeps every page link and explains it in a tooltip', () => {
    renderSidebar()
    const nav = screen.getByRole('navigation', { name: 'Pages' })
    const links = within(nav).getAllByRole('link')
    expect(links).toHaveLength(12)
    for (const link of links) {
      const title = link.getAttribute('title') ?? ''
      expect(title.startsWith(`${link.textContent}: `)).toBe(true)
      expect(title.length).toBeGreaterThan((link.textContent ?? '').length + 10)
    }
    expect(within(nav).getByRole('link', { name: 'WAF Config' })).toBeInTheDocument()
  })
})

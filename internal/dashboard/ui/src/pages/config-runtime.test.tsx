import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ConfigPage from './config'
import { api } from '@/lib/api'

vi.mock('@/lib/api', () => ({ api: {
  getConfig: vi.fn(), getIPACL: vi.fn(), getBans: vi.fn(), updateConfig: vi.fn(),
} }))
const toast = vi.fn()
vi.mock('@/components/ui/toast', () => ({ useToast: () => ({ toast }) }))

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.getConfig).mockResolvedValue({ mode: 'enforce', tls: { enabled: false }, waf: {
    detection: { enabled: true, threshold: { block: 50, log: 25 } },
    sanitizer: { enabled: true, max_body_size: 1024 },
  } })
  vi.mocked(api.getIPACL).mockResolvedValue({ whitelist: [], blacklist: [] })
  vi.mocked(api.getBans).mockResolvedValue({ bans: [] })
  vi.mocked(api.updateConfig).mockResolvedValue({ status: 'ok' })
})

afterEach(cleanup)

describe('configuration runtime contract', () => {
  it('keeps mode editable and makes restart-only TLS settings read-only', async () => {
    render(<ConfigPage />)
    const mode = await screen.findByRole('combobox')
    expect(mode).toBeEnabled()
    fireEvent.click(screen.getByRole('button', { name: /TLS \/ SSL/ }))
    const section = screen.getByRole('button', { name: /TLS \/ SSL/ }).parentElement!
    for (const control of within(section).getAllByRole('switch')) expect(control).toBeDisabled()
    expect(screen.getByText(/Edit restart-only settings in the YAML/)).toBeInTheDocument()
  })

  it('allows live thresholds while preventing detector topology changes', async () => {
    render(<ConfigPage />)
    await screen.findByRole('combobox')
    const section = screen.getByRole('button', { name: /Detection Engine/ }).parentElement!
    const inputs = within(section).getAllByRole('spinbutton')
    expect(inputs[0]).toBeEnabled()
    expect(inputs[1]).toBeEnabled()
    expect(inputs[2]).toBeDisabled()
    for (const control of within(section).getAllByRole('switch')) expect(control).toBeDisabled()
    fireEvent.change(inputs[0], { target: { value: '65' } })
    fireEvent.click(screen.getByRole('button', { name: /Save & Apply/ }))
    await waitFor(() => expect(api.updateConfig).toHaveBeenCalledOnce())
    expect(vi.mocked(api.updateConfig).mock.calls[0][0].waf?.detection.threshold.block).toBe(65)
  })
})

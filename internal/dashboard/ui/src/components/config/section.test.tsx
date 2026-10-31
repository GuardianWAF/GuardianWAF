import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'
import { Section } from './section'

describe('Section', () => {
  it('exposes and updates its expanded state', async () => {
    const user = userEvent.setup()
    render(<Section title="Provider settings"><div>Configuration form</div></Section>)

    const trigger = screen.getByRole('button', { name: 'Provider settings' })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('Configuration form')).not.toBeInTheDocument()

    await user.click(trigger)
    expect(trigger).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('Configuration form')).toBeVisible()
  })

  it('shows its description without changing the button name', () => {
    render(
      <Section title="Rate Limiting" description="Limits how many requests one client can send.">
        <div>Rules</div>
      </Section>,
    )

    const trigger = screen.getByRole('button', { name: 'Rate Limiting' })
    expect(screen.getByText('Limits how many requests one client can send.')).toBeVisible()
    expect(trigger).toHaveAccessibleDescription('Limits how many requests one client can send.')
  })
})

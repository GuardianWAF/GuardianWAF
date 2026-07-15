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
})

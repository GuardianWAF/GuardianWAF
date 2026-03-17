import { useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'

interface SectionProps {
  title: string
  badge?: { on: boolean }
  defaultOpen?: boolean
  children: React.ReactNode
}

export function Section({ title, badge, defaultOpen = false, children }: SectionProps) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className="rounded-lg border border-border bg-card">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between px-5 py-4 text-left transition-colors hover:bg-card/80"
      >
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-foreground">{title}</h3>
          {badge !== undefined && (
            <span
              className={cn(
                'rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider',
                badge.on
                  ? 'bg-success/15 text-success'
                  : 'bg-muted/30 text-muted-foreground',
              )}
            >
              {badge.on ? 'ON' : 'OFF'}
            </span>
          )}
        </div>
        <ChevronDown
          className={cn(
            'h-4 w-4 text-muted-foreground transition-transform duration-200',
            open && 'rotate-180',
          )}
        />
      </button>
      {open && <div className="border-t border-border px-5 py-4">{children}</div>}
    </div>
  )
}

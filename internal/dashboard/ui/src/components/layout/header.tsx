import { useLocation } from 'react-router'
import { Sun, Moon, LogOut } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTheme } from '@/hooks/use-theme'

const breadcrumbMap: Record<string, string> = {
  '/': 'Dashboard',
  '/routing': 'Routing',
  '/config': 'WAF Config',
}

interface HeaderProps {
  connected: boolean
}

export function Header({ connected }: HeaderProps) {
  const location = useLocation()
  const { theme, toggle } = useTheme()

  const pageTitle = breadcrumbMap[location.pathname] ?? 'Dashboard'

  return (
    <header className="flex items-center justify-between h-14 px-6 border-b border-border bg-card/50 backdrop-blur-sm shrink-0">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <span className="text-muted-foreground">GuardianWAF</span>
        <span className="text-muted-foreground">/</span>
        <span className="font-medium text-foreground">{pageTitle}</span>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-4">
        {/* SSE connection status */}
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <div
            className={cn(
              'h-2 w-2 rounded-full',
              connected ? 'bg-success' : 'bg-destructive',
            )}
          />
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>

        {/* Theme toggle */}
        <button
          onClick={toggle}
          className="flex items-center justify-center h-8 w-8 rounded-[var(--radius)] text-muted-foreground hover:bg-card hover:text-foreground transition-colors"
          aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>

        {/* Logout */}
        <a
          href="/logout"
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <LogOut className="h-3.5 w-3.5" />
          <span>Logout</span>
        </a>
      </div>
    </header>
  )
}

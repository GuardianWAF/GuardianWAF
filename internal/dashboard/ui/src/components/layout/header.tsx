import { useLocation } from 'react-router'
import { Sun, Moon, LogOut, Menu } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useTheme } from '@/hooks/use-theme'

const breadcrumbMap: Record<string, string> = {
  '/': 'Dashboard',
  '/routing': 'Routing',
  '/rules': 'Rules',
  '/ssl': 'SSL / TLS',
  '/config': 'WAF Config',
  '/alerting': 'Alerting',
  '/ai': 'AI Analysis',
  '/logs': 'Logs',
  '/analytics': 'Analytics',
  '/docker': 'Docker',
  '/compliance': 'Compliance',
  '/tenants': 'Tenants',
  '/tenants/new': 'New Tenant',
  '/clusters': 'Clusters',
}

interface HeaderProps {
  connected: boolean
  onOpenSidebar: () => void
}

function getPageTitle(pathname: string) {
  if (breadcrumbMap[pathname]) return breadcrumbMap[pathname]
  if (/^\/tenants\/[^/]+\/analytics$/.test(pathname)) return 'Tenant Analytics'
  if (/^\/tenants\/[^/]+$/.test(pathname)) return 'Tenant Details'
  if (/^\/clusters\/[^/]+$/.test(pathname)) return 'Cluster Details'
  return 'Page Not Found'
}

export function Header({ connected, onOpenSidebar }: HeaderProps) {
  const location = useLocation()
  const { theme, toggle } = useTheme()

  const pageTitle = getPageTitle(location.pathname)

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-2 border-b border-border bg-card/50 px-3 backdrop-blur-sm sm:px-6">
      {/* Breadcrumb */}
      <div className="flex min-w-0 items-center gap-2 text-sm">
        <button
          type="button"
          onClick={onOpenSidebar}
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--radius)] text-muted-foreground transition-colors hover:bg-card hover:text-foreground md:hidden"
          aria-label="Open navigation"
        >
          <Menu className="h-5 w-5" />
        </button>
        <span className="hidden text-muted-foreground sm:inline">GuardianWAF</span>
        <span className="hidden text-muted-foreground sm:inline">/</span>
        <span className="truncate font-medium text-foreground">{pageTitle}</span>
      </div>

      {/* Right side */}
      <div className="flex shrink-0 items-center gap-1 sm:gap-3">
        {/* SSE connection status */}
        <div
          className="flex items-center gap-2 text-xs text-muted-foreground"
          role="status"
          aria-label={`Dashboard event stream: ${connected ? 'Connected' : 'Disconnected'}`}
        >
          <div
            className={cn(
              'h-2 w-2 rounded-full',
              connected ? 'bg-success' : 'bg-destructive',
            )}
          />
          <span className="hidden lg:inline">{connected ? 'Connected' : 'Disconnected'}</span>
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
        <form method="POST" action="/logout">
          <button
            type="submit"
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Logout</span>
          </button>
        </form>
      </div>
    </header>
  )
}

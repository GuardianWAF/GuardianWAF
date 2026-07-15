import { useEffect, useState } from 'react'
import { NavLink } from 'react-router'
import { LayoutDashboard, Globe, Settings, ScrollText, Shield, ShieldCheck, PanelLeftClose, PanelLeft, Brain, Bell, Users, Network, KeyRound, ClipboardCheck, BarChart3, Container } from 'lucide-react'
import { cn } from '@/lib/utils'

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/routing', label: 'Routing', icon: Globe },
  { to: '/rules', label: 'Rules', icon: ShieldCheck },
  { to: '/ssl', label: 'SSL/TLS', icon: KeyRound },
  { to: '/config', label: 'WAF Config', icon: Settings },
  { to: '/alerting', label: 'Alerting', icon: Bell },
  { to: '/ai', label: 'AI Analysis', icon: Brain },
  { to: '/logs', label: 'Logs', icon: ScrollText },
  { to: '/analytics', label: 'Analytics', icon: BarChart3 },
  { to: '/docker', label: 'Docker', icon: Container },
  { to: '/compliance', label: 'Compliance', icon: ClipboardCheck },
  { to: '/tenants', label: 'Tenants', icon: Users },
  { to: '/clusters', label: 'Clusters', icon: Network },
]

interface SidebarProps {
  mobileOpen: boolean
  onMobileClose: () => void
}

export function Sidebar({ mobileOpen, onMobileClose }: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false)
  const [isMobile, setIsMobile] = useState(() => window.matchMedia('(max-width: 767px)').matches)

  useEffect(() => {
    const media = window.matchMedia('(max-width: 767px)')
    const handleChange = () => setIsMobile(media.matches)
    handleChange()
    media.addEventListener('change', handleChange)
    return () => media.removeEventListener('change', handleChange)
  }, [])

  useEffect(() => {
    if (!mobileOpen) return

    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onMobileClose()
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [mobileOpen, onMobileClose])

  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[1px] md:hidden"
          onClick={onMobileClose}
        />
      )}
      <aside
        aria-label="Primary navigation"
        aria-hidden={isMobile && !mobileOpen}
        inert={isMobile && !mobileOpen}
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex h-dvh w-64 flex-col border-r border-border bg-sidebar transition-transform duration-200 md:static md:z-auto md:h-screen md:translate-x-0 md:transition-[width]',
          mobileOpen ? 'translate-x-0' : '-translate-x-full',
          collapsed ? 'md:w-16' : 'md:w-56',
        )}
      >
      {/* Logo */}
      <div className="flex items-center gap-2.5 h-14 px-4 border-b border-border shrink-0">
        <Shield className="h-6 w-6 text-accent shrink-0" />
        <span className={cn('text-sm font-semibold text-foreground tracking-tight', collapsed && 'md:hidden')}>
          GuardianWAF
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              cn(
                'flex items-center gap-3 rounded-[var(--radius)] px-3 py-2 text-sm transition-colors',
                collapsed && 'md:justify-center md:px-0',
                isActive
                  ? 'bg-accent/10 text-accent font-medium'
                  : 'text-sidebar-foreground hover:bg-sidebar-accent hover:text-foreground',
              )
            }
            onClick={onMobileClose}
          >
            <Icon className="h-4 w-4 shrink-0" />
            <span className={cn(collapsed && 'md:hidden')}>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Collapse toggle */}
      <div className="hidden border-t border-border p-2 shrink-0 md:block">
        <button
          onClick={() => setCollapsed((c) => !c)}
          className={cn(
            'flex items-center gap-2 w-full rounded-[var(--radius)] px-3 py-2 text-sm text-sidebar-foreground hover:bg-sidebar-accent hover:text-foreground transition-colors',
            collapsed && 'md:justify-center md:px-0',
          )}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed ? (
            <PanelLeft className="h-4 w-4 shrink-0" />
          ) : (
            <>
              <PanelLeftClose className="h-4 w-4 shrink-0" />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
      </aside>
    </>
  )
}

import * as React from 'react'
import { cva } from 'class-variance-authority'
import { cn } from '@/lib/utils'

/* -------------------------------------------------------------------------- */
/*  Toast variant styles                                                      */
/* -------------------------------------------------------------------------- */

const toastVariants = cva(
  'pointer-events-auto relative flex w-full items-center justify-between gap-4 overflow-hidden rounded-[var(--radius-lg)] border border-border p-4 shadow-lg transition-all',
  {
    variants: {
      variant: {
        default: 'bg-card text-card-foreground',
        success: 'border-success/30 bg-success/10 text-success',
        warning: 'border-warning/30 bg-warning/10 text-warning',
        destructive:
          'border-destructive/30 bg-destructive/10 text-destructive',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
)

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface Toast {
  id: string
  title?: string
  description?: string
  variant?: 'default' | 'success' | 'warning' | 'destructive'
  duration?: number
}

interface ToastContextValue {
  toasts: Toast[]
  toast: (t: Omit<Toast, 'id'>) => string
  dismiss: (id: string) => void
}

/* -------------------------------------------------------------------------- */
/*  Context                                                                   */
/* -------------------------------------------------------------------------- */

const ToastContext = React.createContext<ToastContextValue | null>(null)

function useToast(): ToastContextValue {
  const ctx = React.useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}

/* -------------------------------------------------------------------------- */
/*  Provider                                                                  */
/* -------------------------------------------------------------------------- */

let toastCounter = 0

function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<Toast[]>([])

  const dismiss = React.useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const toast = React.useCallback(
    (t: Omit<Toast, 'id'>) => {
      const id = `toast-${++toastCounter}`
      const duration = t.duration ?? 4000

      setToasts((prev) => [...prev, { ...t, id }])

      if (duration > 0) {
        setTimeout(() => dismiss(id), duration)
      }

      return id
    },
    [dismiss],
  )

  const value = React.useMemo(
    () => ({ toasts, toast, dismiss }),
    [toasts, toast, dismiss],
  )

  return (
    <ToastContext.Provider value={value}>
      {children}
      <ToastViewport toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  )
}

/* -------------------------------------------------------------------------- */
/*  Viewport (renders toasts in bottom-right)                                 */
/* -------------------------------------------------------------------------- */

interface ToastViewportProps {
  toasts: Toast[]
  onDismiss: (id: string) => void
}

function ToastViewport({ toasts, onDismiss }: ToastViewportProps) {
  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-[100] flex max-w-sm flex-col-reverse gap-2">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />
      ))}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/*  Single toast item                                                         */
/* -------------------------------------------------------------------------- */

function ToastItem({
  toast: t,
  onDismiss,
}: {
  toast: Toast
  onDismiss: (id: string) => void
}) {
  return (
    <div
      className={cn(
        toastVariants({ variant: t.variant }),
        'animate-in slide-in-from-bottom-2 fade-in-0',
      )}
      role="alert"
    >
      <div className="flex-1">
        {t.title && <p className="text-sm font-semibold">{t.title}</p>}
        {t.description && (
          <p className="text-sm opacity-90">{t.description}</p>
        )}
      </div>
      <button
        type="button"
        className="shrink-0 rounded-[var(--radius)] p-1 opacity-70 transition-opacity hover:opacity-100"
        onClick={() => onDismiss(t.id)}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
        >
          <path d="M18 6 6 18" />
          <path d="m6 6 12 12" />
        </svg>
      </button>
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/*  Exports                                                                   */
/* -------------------------------------------------------------------------- */

export { ToastProvider, useToast, toastVariants }
export type { Toast, ToastContextValue }

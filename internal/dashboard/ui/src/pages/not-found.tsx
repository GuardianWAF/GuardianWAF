import { ArrowLeft, LayoutDashboard } from 'lucide-react'
import { Link } from 'react-router'
import { Card, CardContent } from '@/components/ui/card'

export default function NotFoundPage() {
  return (
    <div className="mx-auto flex min-h-[60vh] max-w-xl items-center justify-center">
      <Card className="w-full">
        <CardContent className="flex flex-col items-center px-6 py-12 text-center">
          <div className="mb-5 flex h-14 w-14 items-center justify-center rounded-full bg-accent/10 text-accent">
            <LayoutDashboard className="h-7 w-7" />
          </div>
          <p className="mb-2 text-sm font-medium text-accent">404</p>
          <h1 className="text-2xl font-semibold text-foreground">Page not found</h1>
          <p className="mt-2 max-w-sm text-sm text-muted-foreground">
            The dashboard page you requested does not exist or may have moved.
          </p>
          <Link
            to="/"
            className="mt-6 inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-[var(--radius)] bg-accent px-4 py-2 text-sm font-medium text-accent-foreground shadow-sm transition-colors hover:bg-accent/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to dashboard
          </Link>
        </CardContent>
      </Card>
    </div>
  )
}

import { FormEvent, ReactNode, useState } from 'react'
import { Key, LogOut } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { api } from '@/lib/api'

interface AdminKeyGateProps {
  children: ReactNode
  locked?: boolean
  onLocked?: () => void
  onUnlocked?: () => void
}

export function AdminKeyGate({ children, locked = false, onLocked, onUnlocked }: AdminKeyGateProps) {
  const [unlocked, setUnlocked] = useState(api.hasAdminKey())
  const [adminKey, setAdminKey] = useState('')
  const isUnlocked = unlocked && !locked

  const submit = (event: FormEvent) => {
    event.preventDefault()
    api.setAdminKey(adminKey)
    setAdminKey('')
    setUnlocked(true)
    onUnlocked?.()
  }

  const clear = () => {
    api.clearAdminKey()
    setUnlocked(false)
    onLocked?.()
  }

  if (isUnlocked) {
    return (
      <div className="space-y-4">
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={clear}>
            <LogOut className="w-4 h-4 mr-2" />
            Clear admin key
          </Button>
        </div>
        {children}
      </div>
    )
  }

  return (
    <Card className="max-w-xl">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-lg">
          <Key className="w-5 h-5" />
          Admin key required
        </CardTitle>
      </CardHeader>
      <CardContent>
        <form className="space-y-4" onSubmit={submit}>
          <div className="space-y-2">
            <Label htmlFor="admin-key">dashboard.admin_key</Label>
            <Input
              id="admin-key"
              type="password"
              value={adminKey}
              onChange={(event) => setAdminKey(event.target.value)}
              autoComplete="off"
              required
            />
          </div>
          <Button type="submit">
            <Key className="w-4 h-4 mr-2" />
            Unlock
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

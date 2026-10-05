import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { ApiError } from '../api'

// ---------- Modal ----------

interface ModalProps {
  title: string
  onClose: () => void
  children: ReactNode
  footer?: ReactNode
  wide?: boolean
}

export function Modal({ title, onClose, children, footer, wide }: ModalProps) {
  const titleId = useId()
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    document.addEventListener('keydown', onKey)
    // the first field of the form, or the last button of the footer (the main action)
    const field = panel.current?.querySelector<HTMLElement>('input:not([disabled]):not([readonly]), textarea, select')
    const buttons = panel.current?.querySelectorAll<HTMLElement>('button')
    ;(field ?? buttons?.[buttons.length - 1])?.focus()
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/50 p-4 sm:p-8" onMouseDown={onClose}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className={`card w-full ${wide ? 'max-w-3xl' : 'max-w-lg'} mt-8`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-200 px-5 py-3 dark:border-slate-800">
          <h2 id={titleId} className="text-base font-semibold">
            {title}
          </h2>
          <button type="button" className="btn-ghost" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <div className="px-5 py-4">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-slate-200 px-5 py-3 dark:border-slate-800">{footer}</div>}
      </div>
    </div>
  )
}

// ---------- Confirmation ----------

interface ConfirmOptions {
  title: string
  message: ReactNode
  confirmLabel: string
  danger?: boolean
}

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>

const ConfirmContext = createContext<ConfirmFn>(() => Promise.resolve(false))

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<(ConfirmOptions & { resolve: (value: boolean) => void }) | null>(null)

  const confirm = useCallback<ConfirmFn>((options) => new Promise((resolve) => setState({ ...options, resolve })), [])
  const close = (value: boolean) => {
    state?.resolve(value)
    setState(null)
  }

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {state && (
        <Modal
          title={state.title}
          onClose={() => close(false)}
          footer={
            <>
              <button type="button" className="btn-secondary" onClick={() => close(false)}>
                Cancel
              </button>
              <button type="button" className={state.danger ? 'btn-danger' : 'btn-primary'} onClick={() => close(true)}>
                {state.confirmLabel}
              </button>
            </>
          }
        >
          <div className="text-sm text-slate-600 dark:text-slate-300">{state.message}</div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  )
}

export const useConfirm = () => useContext(ConfirmContext)

// ---------- Toasts ----------

interface Toast {
  id: number
  kind: 'success' | 'error'
  message: string
}

type NotifyFn = (kind: Toast['kind'], message: string) => void

const ToastContext = createContext<NotifyFn>(() => undefined)

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const nextId = useRef(0)

  const notify = useCallback<NotifyFn>((kind, message) => {
    const id = nextId.current++
    setToasts((current) => [...current, { id, kind, message }])
    setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), kind === 'error' ? 8000 : 4000)
  }, [])

  return (
    <ToastContext.Provider value={notify}>
      {children}
      <div className="fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.kind === 'error' ? 'alert' : 'status'}
            className={`rounded-md px-4 py-3 text-sm shadow-lg ${
              t.kind === 'error' ? 'bg-red-600 text-white' : 'bg-slate-800 text-white dark:bg-slate-100 dark:text-slate-900'
            }`}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export const useToast = () => useContext(ToastContext)

/** the login page, to come back to this page after a new login */
export function reauthenticationURL() {
  const page = window.location.pathname + window.location.hash
  return new URL(`../login?return_url=${encodeURIComponent(page)}`, window.location.href).toString()
}

/** runs an action showing its result in a toast. Returns true if it succeeded */
export function useAction() {
  const notify = useToast()
  const confirm = useConfirm()
  return useCallback(
    async (action: () => Promise<unknown>, success?: string) => {
      try {
        await action()
        if (success) notify('success', success)
        return true
      } catch (e) {
        // the sensitive actions need a recent login
        if (e instanceof ApiError && e.reauthenticate) {
          const ok = await confirm({
            title: 'Sign in again',
            message:
              'For your security, sign in again to change the credentials or the state of an account. You will come back to this page.',
            confirmLabel: 'Sign in',
          })
          if (ok) window.location.assign(reauthenticationURL())
          return false
        }

        notify('error', e instanceof Error ? e.message : String(e))
        return false
      }
    },
    [notify, confirm],
  )
}

// ---------- Small pieces ----------

export function Field({ label, hint, children, htmlFor }: { label: string; hint?: ReactNode; children: ReactNode; htmlFor?: string }) {
  return (
    <div>
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {hint && <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  )
}

const badgeColors = {
  gray: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300',
  indigo: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300',
  green: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-300',
  red: 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-300',
  amber: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
}

export function Badge({ color = 'gray', children, title }: { color?: keyof typeof badgeColors; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${badgeColors[color]}`} title={title}>
      {children}
    </span>
  )
}

export function Spinner() {
  return (
    <div className="flex justify-center py-12" role="status" aria-label="Loading">
      <div className="h-6 w-6 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600" />
    </div>
  )
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="px-4 py-12 text-center text-sm text-slate-500 dark:text-slate-400">{children}</div>
}

/** shows a generated secret: it is only returned once by the server */
export function SecretDialog({ clientId, secret, onClose }: { clientId: string; secret: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    await navigator.clipboard.writeText(secret)
    setCopied(true)
  }

  return (
    <Modal
      title={`Secret of ${clientId}`}
      onClose={onClose}
      footer={
        <button type="button" className="btn-primary" onClick={onClose}>
          I have saved it
        </button>
      }
    >
      <p className="mb-3 text-sm text-amber-700 dark:text-amber-400">Copy the secret now: it will not be shown again.</p>
      <div className="flex gap-2">
        <input className="input font-mono" readOnly value={secret} onFocus={(e) => e.target.select()} aria-label="Client secret" />
        <button type="button" className="btn-secondary shrink-0" onClick={copy}>
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
    </Modal>
  )
}

/** a list of groups: chips, and a text field that suggests the existing groups */
export function GroupPicker({
  id,
  value,
  onChange,
  suggestions,
  placeholder,
}: {
  id: string
  value: string[]
  onChange: (value: string[]) => void
  suggestions: string[]
  placeholder?: string
}) {
  const [text, setText] = useState('')
  const listId = useId()
  const has = (name: string) => value.some((v) => v.toLowerCase() === name.toLowerCase())

  const add = (name: string) => {
    const group = name.trim()
    setText('')
    if (group && !has(group)) onChange([...value, group].sort((a, b) => a.localeCompare(b)))
  }

  return (
    <div className="input flex flex-wrap items-center gap-1.5 py-1.5 focus-within:border-indigo-500 focus-within:ring-3 focus-within:ring-indigo-500/20">
      {value.map((group) => (
        <span key={group} className="badge gap-1 bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
          {group}
          <button
            type="button"
            className="text-slate-500 hover:text-slate-900 dark:hover:text-white"
            aria-label={`Remove ${group}`}
            onClick={() => onChange(value.filter((v) => v !== group))}
          >
            ×
          </button>
        </span>
      ))}
      <input
        id={id}
        list={listId}
        className="min-w-28 flex-1 bg-transparent py-0.5 outline-none"
        value={text}
        placeholder={value.length === 0 ? placeholder : ''}
        onChange={(e) => {
          // a suggestion chosen in the list is added at once
          if (suggestions.includes(e.target.value)) add(e.target.value)
          else setText(e.target.value)
        }}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ',') {
            e.preventDefault()
            add(text)
          } else if (e.key === 'Backspace' && text === '' && value.length > 0) {
            onChange(value.slice(0, -1))
          }
        }}
        onBlur={() => add(text)}
      />
      <datalist id={listId}>
        {suggestions
          .filter((s) => !has(s))
          .map((s) => (
            <option key={s} value={s} />
          ))}
      </datalist>
    </div>
  )
}

/** a value that can be copied (e.g. a generated password or link) */
export function CopyField({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    await navigator.clipboard.writeText(value)
    setCopied(true)
  }

  return (
    <div className="flex gap-2">
      <input className="input font-mono" readOnly value={value} onFocus={(e) => e.target.select()} aria-label={label} />
      <button type="button" className="btn-secondary shrink-0" onClick={copy}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

export interface MenuItem {
  label: string
  onSelect: () => void
  danger?: boolean
  hidden?: boolean
}

const menuWidth = 208

/** a button with a list of actions. The list is in a portal, so the scroll
 * containers (e.g. the tables) do not cut it */
export function Menu({ label, items }: { label: string; items: MenuItem[] }) {
  const [position, setPosition] = useState<{
    top: number
    left: number
  } | null>(null)
  const button = useRef<HTMLButtonElement>(null)
  const list = useRef<HTMLDivElement>(null)
  const menuId = useId()
  const open = position !== null

  useEffect(() => {
    if (!open) return
    const close = () => setPosition(null)
    const onClick = (e: MouseEvent) => {
      const target = e.target as Node
      if (!list.current?.contains(target) && !button.current?.contains(target)) close()
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close()
    document.addEventListener('mousedown', onClick)
    document.addEventListener('keydown', onKey)
    window.addEventListener('scroll', close, true)
    window.addEventListener('resize', close)
    list.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('mousedown', onClick)
      document.removeEventListener('keydown', onKey)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('resize', close)
    }
  }, [open])

  const visible = items.filter((item) => !item.hidden)
  if (visible.length === 0) return null

  const toggle = () => {
    if (open || !button.current) {
      setPosition(null)
      return
    }

    // below the button, aligned to its right side; above it if there is no room
    const rect = button.current.getBoundingClientRect()
    const height = visible.length * 36 + 8
    const top = rect.bottom + 4 + height > window.innerHeight ? Math.max(8, rect.top - 4 - height) : rect.bottom + 4
    setPosition({ top, left: Math.max(8, rect.right - menuWidth) })
  }

  return (
    <>
      <button
        ref={button}
        type="button"
        className="btn-ghost"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={menuId}
        onClick={toggle}
      >
        {label}
        <span aria-hidden="true">▾</span>
      </button>
      {position &&
        createPortal(
          <div
            ref={list}
            id={menuId}
            role="menu"
            className="card fixed z-50 py-1 shadow-lg"
            style={{ top: position.top, left: position.left, width: menuWidth }}
          >
            {visible.map((item) => (
              <button
                key={item.label}
                type="button"
                role="menuitem"
                className={`block w-full px-3 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-800 ${
                  item.danger ? 'text-red-600 dark:text-red-400' : ''
                }`}
                onClick={() => {
                  setPosition(null)
                  item.onSelect()
                }}
              >
                {item.label}
              </button>
            ))}
          </div>,
          document.body,
        )}
    </>
  )
}

export const formatDate = (value: string) =>
  new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

/** splits a text in lines, without empty ones */
export const lines = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

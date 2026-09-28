import { createContext, useCallback, useContext, useEffect, useId, useRef, useState, type ReactNode } from 'react'

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

/** runs an action showing its result in a toast. Returns true if it succeeded */
export function useAction() {
  const notify = useToast()
  return useCallback(
    async (action: () => Promise<unknown>, success?: string) => {
      try {
        await action()
        if (success) notify('success', success)
        return true
      } catch (e) {
        notify('error', e instanceof Error ? e.message : String(e))
        return false
      }
    },
    [notify],
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

export const formatDate = (value: string) =>
  new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

/** splits a text in lines, without empty ones */
export const lines = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

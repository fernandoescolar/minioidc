import { useCallback, useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, settingsExportURL, type Setting, type Settings } from '../api'
import { Badge, Spinner, useAction } from '../components/ui'
import { MaintenancePage } from './Maintenance'

/** the settings of the configuration file, the server information and the maintenance */
export function SettingsPage() {
  const [settings, setSettings] = useState<Settings | null>(null)
  const [values, setValues] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState(false)
  const run = useAction()

  const show = useCallback((loaded: Settings) => {
    setSettings(loaded)
    setValues(Object.fromEntries(loaded.settings.map((s) => [s.key, s.value])))
  }, [])

  useEffect(() => {
    run(async () => show(await api.settings()))
  }, [run, show])

  const groups = useMemo(() => {
    const result = new Map<string, Setting[]>()
    for (const s of settings?.settings ?? []) result.set(s.group, [...(result.get(s.group) ?? []), s])
    return [...result.entries()]
  }, [settings])

  if (!settings) return <Spinner />

  const changed = settings.settings.filter((s) => values[s.key] !== s.value)
  const pending = settings.settings.filter((s) => s.pending)

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setSaving(true)
    await run(async () => {
      show(await api.updateSettings(settings.version ?? '', Object.fromEntries(changed.map((s) => [s.key, values[s.key]]))))
    }, 'Settings saved: restart the server to apply them')
    setSaving(false)
  }

  return (
    <section className="flex flex-col gap-4">
      <div>
        <h1 className="text-xl font-semibold">Settings</h1>
        {settings.mode === 'file' ? (
          <p className="text-sm text-slate-500 dark:text-slate-400">
            The settings of <code className="font-mono">{settings.file}</code>. The changes are written in the file (the previous
            one is kept as <code className="font-mono">.bak</code>) and apply when the server restarts.
          </p>
        ) : (
          <p className="text-sm text-slate-500 dark:text-slate-400">The settings of the default configuration.</p>
        )}
      </div>

      {settings.read_only_reason && (
        <div className="alert-info flex flex-wrap items-center justify-between gap-3">
          <span>{settings.read_only_reason}</span>
          {settings.mode === 'default' && (
            <a className="btn-secondary" href={settingsExportURL()} download>
              Download configuration
            </a>
          )}
        </div>
      )}

      {pending.length > 0 && (
        <div className="alert-warning">
          <strong>Restart the server to apply:</strong> {pending.map((s) => s.label).join(', ')}.
        </div>
      )}

      <form onSubmit={submit} className="flex flex-col gap-4">
        {groups.map(([group, items]) => (
          <div key={group} className="card p-5">
            <h2 className="mb-3 font-semibold">{group}</h2>
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {items.map((s) => (
                <SettingRow
                  key={s.key}
                  setting={s}
                  value={values[s.key] ?? ''}
                  disabled={!settings.editable || s.from_env}
                  onChange={(value) => setValues((v) => ({ ...v, [s.key]: value }))}
                />
              ))}
            </div>
          </div>
        ))}

        {settings.editable && (
          <div className="sticky bottom-4 flex flex-wrap items-center justify-end gap-3 rounded-xl border border-slate-200 bg-white/90 p-3 shadow-sm backdrop-blur dark:border-slate-800 dark:bg-slate-900/90">
            <span className="text-sm text-slate-500 dark:text-slate-400">
              {changed.length === 0 ? 'No changes' : `${changed.length} ${changed.length === 1 ? 'change' : 'changes'}`}
            </span>
            <button
              type="button"
              className="btn-secondary"
              disabled={changed.length === 0}
              onClick={() => setValues(Object.fromEntries(settings.settings.map((s) => [s.key, s.value])))}
            >
              Discard
            </button>
            <button type="submit" className="btn-primary" disabled={changed.length === 0 || saving}>
              {saving ? 'Saving…' : 'Save'}
            </button>
          </div>
        )}
      </form>

      <div className="card p-5">
        <h2 className="font-semibold">Server</h2>
        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
          These settings are changed in the configuration file: changing them can break the clients or the passkeys, or lock the
          administrators out.
        </p>
        <dl className="mt-3 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
          {settings.server.map((item) => (
            <div key={item.label} className="contents">
              <dt className="text-slate-500 dark:text-slate-400">{item.label}</dt>
              <dd className="font-mono break-all">{item.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div>
        <h2 className="mb-3 font-semibold">Maintenance</h2>
        <MaintenancePage />
      </div>
    </section>
  )
}

function SettingRow({
  setting,
  value,
  disabled,
  onChange,
}: {
  setting: Setting
  value: string
  disabled: boolean
  onChange: (value: string) => void
}) {
  const id = `setting-${setting.key}`
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 py-3">
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="flex flex-wrap items-center gap-2 text-sm font-medium">
          {setting.label}
          {setting.from_env && <Badge title="The file reads it from an environment variable">{setting.value}</Badge>}
          {setting.pending && <Badge color="amber">restart pending</Badge>}
        </label>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {setting.description}
          {setting.description && ' '}
          Default: {setting.default}.{setting.pending && ` Running: ${setting.running}.`}
        </p>
      </div>
      {setting.kind === 'bool' ? (
        <input
          id={id}
          type="checkbox"
          className="h-5 w-5 accent-indigo-600"
          disabled={disabled}
          checked={value === 'true'}
          onChange={(e) => onChange(String(e.target.checked))}
        />
      ) : (
        <input
          id={id}
          type={setting.kind === 'int' ? 'number' : 'text'}
          className="input w-40"
          disabled={disabled}
          min={setting.min}
          max={setting.kind === 'int' ? setting.max : undefined}
          maxLength={setting.kind === 'string' ? setting.max : undefined}
          value={setting.from_env ? '' : value}
          placeholder={setting.from_env ? 'environment variable' : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
    </div>
  )
}

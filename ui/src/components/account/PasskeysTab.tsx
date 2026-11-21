import { useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { listPasskeys, passkeyErrorKey, registerPasskey, removePasskey, supportsPasskeys, type Passkey } from '../../api/passkeys'
import { EmptyState, EntityCard, IconButton, LockIcon, PlusIcon, TrashIcon } from '../common/listui'

interface PasskeysTabProps {
  userID: string
  requiresTOTP: boolean
}

type Editor = { type: 'add' } | { type: 'remove'; key: Passkey }

const field = 'block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-slate-900 focus:border-primary-500 focus:outline-none focus:ring-2 focus:ring-primary-500/30 disabled:opacity-60 dark:border-slate-600 dark:bg-slate-700 dark:text-white'
const label = 'block space-y-1.5 font-medium text-slate-700 dark:text-slate-300'
const action = 'rounded-lg px-4 py-2 text-sm font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-500 disabled:cursor-not-allowed disabled:opacity-50'

export function PasskeysTab({ userID, requiresTOTP }: PasskeysTabProps) {
  const { t, i18n } = useTranslation(['auth', 'common'])
  const queryClient = useQueryClient()
  const queryKey = ['account-passkeys', userID]
  const keys = useQuery({ queryKey, queryFn: listPasskeys, retry: false })
  const supported = supportsPasskeys()
  const heading = useRef<HTMLHeadingElement>(null)
  const [editor, setEditor] = useState<Editor | null>(null)
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const removing = editor?.type === 'remove' ? editor.key : null

  const openEditor = (next: Editor) => {
    setEditor(next)
    setName('')
    setPassword('')
    setCode('')
    setError('')
    setSuccess('')
  }

  const closeEditor = () => {
    setEditor(null)
    setPassword('')
    setCode('')
    setError('')
    heading.current?.focus()
  }

  const submit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!editor || busy) return
    setBusy(true)
    setError('')
    const proof = { password, totp_code: code }
    setPassword('')
    setCode('')
    try {
      if (removing) {
        await removePasskey(removing.id, proof)
      } else {
        await registerPasskey(name.trim(), proof)
      }
      await queryClient.invalidateQueries({ queryKey })
      closeEditor()
      setSuccess(t(removing ? 'passkeys.removed' : 'passkeys.registered'))
    } catch (failure) {
      setError(t(passkeyErrorKey(failure), { defaultValue: t('passkeys.errors.failed') }))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section aria-labelledby="passkeys-heading" className="space-y-4 text-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-64">
          <h3 id="passkeys-heading" ref={heading} tabIndex={-1} className="text-lg font-semibold text-slate-900 dark:text-white">
            {t('passkeys.title')}
          </h3>
          <p className="mt-1 leading-6 text-slate-500 dark:text-slate-400">{t('passkeys.description')}</p>
        </div>
        {supported && !editor && (
          <button type="button" onClick={() => openEditor({ type: 'add' })}
            className={`${action} inline-flex shrink-0 items-center gap-1.5 bg-primary-600 text-white shadow-sm hover:bg-primary-700`}>
            <span aria-hidden="true"><PlusIcon /></span>
            {t('passkeys.add')}
          </button>
        )}
      </div>

      {!supported && (
        <p className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-amber-800 dark:border-amber-800 dark:bg-amber-900/20 dark:text-amber-200">
          {t('passkeys.unsupported')}
        </p>
      )}

      {success && (
        <p role="status" className="rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-green-800 dark:border-green-800 dark:bg-green-900/20 dark:text-green-200">
          {success}
        </p>
      )}

      {editor && (
        <form key={removing?.id ?? editor.type} onSubmit={submit} aria-busy={busy} aria-label={t(removing ? 'common:buttons.remove' : 'passkeys.add')}
          className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-900/40">
          <fieldset disabled={busy} className="min-w-0 space-y-4">
            {removing ? (
              <p className="wrap-anywhere rounded-lg border border-red-200 bg-red-50 px-3 py-2 leading-6 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
                {t('passkeys.confirmRemove', { name: removing.name })}
              </p>
            ) : (
              <label className={label}>
                <span>{t('passkeys.name')}</span>
                <input autoFocus className={field} value={name} onChange={(event) => setName(event.target.value)} maxLength={80} required />
              </label>
            )}
            <div className={requiresTOTP ? 'grid gap-4 sm:grid-cols-2' : undefined}>
              <label className={label}>
                <span>{t('account.password.currentPassword')}</span>
                <input autoFocus={!!removing} type="password" autoComplete="current-password" className={field} value={password}
                  onChange={(event) => setPassword(event.target.value)} required />
              </label>
              {requiresTOTP && (
                <label className={label}>
                  <span>{t('passkeys.totpCode')}</span>
                  <input inputMode="numeric" autoComplete="one-time-code" className={`${field} font-mono tracking-wider`} value={code}
                    onChange={(event) => setCode(event.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                    pattern="[0-9]{6}" maxLength={6} placeholder="000000" required />
                </label>
              )}
            </div>
            {error && (
              <p role="alert" className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
                {error}
              </p>
            )}
            <div className="flex flex-wrap justify-end gap-2">
              <button type="button" onClick={closeEditor}
                className={`${action} text-slate-700 hover:bg-slate-100 dark:text-slate-200 dark:hover:bg-slate-700`}>
                {t('common:buttons.cancel')}
              </button>
              <button type="submit" disabled={!removing && !name.trim()}
                className={`${action} text-white ${removing ? 'bg-red-600 hover:bg-red-700' : 'bg-primary-600 hover:bg-primary-700'}`}>
                {busy
                  ? t(removing ? 'common:status.deleting' : 'passkeys.waitingForKey')
                  : t(removing ? 'common:buttons.remove' : 'passkeys.add')}
              </button>
            </div>
          </fieldset>
        </form>
      )}

      {keys.isPending && (
        <p role="status" className="rounded-lg border border-slate-200 px-4 py-5 text-center text-slate-500 dark:border-slate-700 dark:text-slate-400">
          {t('common:status.loading')}
        </p>
      )}
      {keys.isError && (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-3 text-red-800 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
          <p role="alert">{t('passkeys.loadFailed')}</p>
          <button type="button" disabled={keys.isFetching} onClick={() => { void keys.refetch() }}
            className={`${action} hover:bg-red-100 dark:hover:bg-red-900/40`}>
            {t('common:buttons.retry')}
          </button>
        </div>
      )}
      {keys.data?.length === 0 && (
        <EmptyState icon={<LockIcon className="h-5 w-5" />}>{t('passkeys.empty')}</EmptyState>
      )}
      {!!keys.data?.length && (
        <ul className="space-y-2">
          {keys.data.map((key) => (
            <li key={key.id}>
              <EntityCard active={removing?.id === key.id}>
                <div className="flex items-start gap-3 p-3 sm:items-center sm:p-4">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-300">
                    <LockIcon />
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="wrap-anywhere font-medium text-slate-900 dark:text-white" dir="auto">{key.name}</p>
                    <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
                      <span className="wrap-anywhere" dir="ltr">{key.rp_id}</span>
                      <span>{t('passkeys.lastUsed', { time: key.last_used_at ? new Date(key.last_used_at).toLocaleString(i18n.language) : t('account.info.never') })}</span>
                    </div>
                  </div>
                  <IconButton title={t('common:buttons.remove')} variant="danger"
                    disabled={!!editor || !window.isSecureContext} onClick={() => openEditor({ type: 'remove', key })}>
                    <TrashIcon />
                  </IconButton>
                </div>
              </EntityCard>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

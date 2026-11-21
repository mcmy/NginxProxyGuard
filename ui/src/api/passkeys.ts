import { getAuthHeaders, setToken } from './auth'

export interface Passkey {
  id: string
  name: string
  rp_id: string
  created_at: string
  last_used_at?: string
}

interface PasskeyOptions<T> {
  flow_id: string
  options: { publicKey: T }
}

interface PasskeyProof {
  password: string
  totp_code: string
}

export function supportsPasskeys(): boolean {
  return window.isSecureContext &&
    typeof PublicKeyCredential !== 'undefined' &&
    typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' &&
    typeof PublicKeyCredential.prototype.toJSON === 'function'
}

async function request(path: string, method: string, authenticated: boolean, body?: unknown): Promise<Response> {
  const response = await fetch(`/api/v1/auth${path}`, {
    method,
    headers: authenticated ? getAuthHeaders() : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    const data = await response.json().catch(() => null)
    throw new Error(response.status === 429 ? 'rate_limited' : data?.code || 'failed')
  }
  return response
}

export async function signInWithPasskey(): Promise<void> {
  const begin = await request('/passkey/login/begin', 'POST', false)
  const { flow_id, options }: PasskeyOptions<PublicKeyCredentialRequestOptionsJSON> = await begin.json()
  const credential = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options.publicKey),
  })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('verification_failed')
  const finish = await request('/passkey/login/finish', 'POST', false, { flow_id, credential: credential.toJSON() })
  const { token } = await finish.json()
  if (!token) throw new Error('failed')
  setToken(token)
}

export async function listPasskeys(): Promise<Passkey[]> {
  const response = await request('/passkeys', 'GET', true)
  return response.json()
}

export async function registerPasskey(name: string, proof: PasskeyProof): Promise<void> {
  const begin = await request('/passkeys/register/begin', 'POST', true, { name, ...proof })
  const { flow_id, options }: PasskeyOptions<PublicKeyCredentialCreationOptionsJSON> = await begin.json()
  const credential = await navigator.credentials.create({
    publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options.publicKey),
  })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('verification_failed')
  await request('/passkeys/register/finish', 'POST', true, { flow_id, credential: credential.toJSON() })
}

export async function removePasskey(id: string, proof: PasskeyProof): Promise<void> {
  await request(`/passkeys/${encodeURIComponent(id)}`, 'DELETE', true, proof)
}

export function passkeyErrorKey(error: unknown): string {
  if (error instanceof DOMException && ['NotAllowedError', 'AbortError'].includes(error.name)) {
    return 'passkeys.errors.cancelled'
  }
  return `passkeys.errors.${error instanceof Error ? error.message : 'failed'}`
}

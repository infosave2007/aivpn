import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { RP_NAME, config } from '../config'

export interface TotpSetup {
  secret: string      // plaintext base32 — returned to user for QR scan, never stored as-is
  otpauth_url: string
  qr_data_url: string // data:image/png;base64,...
}

// ─── AES-256-GCM encryption for TOTP secrets at rest ─────────────────────────

function getTotpKey(): Buffer {
  if (!config.TOTP_ENCRYPTION_KEY) {
    throw new Error(
      'TOTP_ENCRYPTION_KEY is not set. Generate one with: openssl rand -base64 32',
    )
  }
  const key = Buffer.from(config.TOTP_ENCRYPTION_KEY, 'base64')
  if (key.length !== 32) {
    throw new Error('TOTP_ENCRYPTION_KEY must be a base64-encoded 32-byte key')
  }
  return key
}

// Returns base64(iv[12] + tag[16] + ciphertext)
export function encryptTotpSecret(plaintext: string): string {
  const key = getTotpKey()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return Buffer.concat([iv, tag, encrypted]).toString('base64')
}

export function decryptTotpSecret(encoded: string): string {
  const key = getTotpKey()
  const buf = Buffer.from(encoded, 'base64')
  const decipher = createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12))
  decipher.setAuthTag(buf.subarray(12, 28))
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8')
}

// ─── TOTP generation / verification ──────────────────────────────────────────

export async function generateTotpSecret(username: string): Promise<TotpSetup> {
  const secret = speakeasy.generateSecret({
    name: `${RP_NAME} (${username})`,
    length: 20,
  })

  const otpauth_url = secret.otpauth_url!
  const qr_data_url = await QRCode.toDataURL(otpauth_url)

  return {
    secret: secret.base32,
    otpauth_url,
    qr_data_url,
  }
}

const TOTP_STEP_SECONDS = 30

/**
 * Verify a TOTP code. Returns the accepted RFC 6238 time step on success,
 * or null on failure.
 *
 * RFC 6238 §5.2 requires each code to be accepted at most once — the caller
 * MUST persist the returned step (users.totp_last_step) and reject any code
 * whose step is <= the last accepted one, otherwise an observed code is
 * replayable for its full ±window validity (~90 s).
 */
export function verifyTotpToken(secret: string, token: string): number | null {
  const result = speakeasy.totp.verifyDelta({
    secret,
    encoding: 'base32',
    token,
    window: 1,
  })
  if (!result) return null
  return Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS) + result.delta
}

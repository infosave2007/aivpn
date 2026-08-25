import { z } from 'zod'

const envSchema = z.object({
  DATABASE_URL: z.string().default('file:./data/aivpn-web.db'),
  JWT_SECRET: z
    .string()
    .min(32, 'JWT_SECRET must be at least 32 characters')
    .refine((v) => v !== 'change-me-to-a-long-random-string', {
      message: 'JWT_SECRET is still the .env.example placeholder — generate a real secret (openssl rand -base64 48)',
    }),
  // Origin for WebAuthn and CORS — must match the browser-facing URL
  ORIGIN: z.string().url().default('http://localhost:3000'),
  // Unix socket path for the aivpn management API
  UNIX_SOCK: z.string().default('/run/aivpn/api.sock'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  // In dev mode proxy frontend to SvelteKit dev server
  DEV_MODE: z
    .string()
    .transform((v) => v === 'true' || v === '1')
    .default('false'),
  SVELTEKIT_DEV_PORT: z.coerce.number().int().default(5173),
  // Path to built SvelteKit client, relative to the dist/ bundle directory
  CLIENT_BUILD_DIR: z.string().default('client/build'),
  // AES-256-GCM key for encrypting TOTP secrets at rest.
  // Generate: openssl rand -base64 32
  // Required for production; if absent TOTP setup/verify will throw.
  TOTP_ENCRYPTION_KEY: z
    .string()
    .refine((v) => v !== 'change-me-generate-with-openssl-rand-base64-32', {
      message: 'TOTP_ENCRYPTION_KEY is still the .env.example placeholder — generate 32 raw bytes (openssl rand -base64 32); a default key means all TOTP seeds are encrypted under a world-known key',
    })
    .optional(),
  // Optional initial admin password. When set (>= 8 chars), the first-run
  // bootstrap seeds the `admin` user with it instead of a random password.
  // When absent, a random password is generated and printed once to the console.
  AIVPN_WEB_ADMIN_PASSWORD: z.string().min(8).optional(),
  // OIDC/SSO — optional; mode 'disabled' (default) means no SSO button
  OIDC_ISSUER: z.string().optional(),
  OIDC_CLIENT_ID: z.string().optional(),
  OIDC_CLIENT_SECRET: z.string().optional(),
  OIDC_MODE: z.enum(['disabled', 'enabled', 'exclusive']).default('disabled'),
  // Claim name whose value is checked to assign admin role on first SSO login.
  // e.g. OIDC_ROLE_CLAIM=role, OIDC_ADMIN_VALUE=admin
  // The role is only set on first login; admins can override it later via the panel.
  OIDC_ROLE_CLAIM: z.string().default(''),
  OIDC_ADMIN_VALUE: z.string().default('admin'),
  // Trust X-Forwarded-For / X-Real-IP for client IP resolution (rate limits,
  // audit log, session records). MUST stay false unless the panel sits behind
  // a trusted reverse proxy (e.g. nginx) that OVERWRITES these headers —
  // otherwise any client can spoof its IP to bypass rate limits and forge
  // audit entries. Default: false (use the real socket peer address).
  AIVPN_WEB_TRUST_PROXY: z
    .string()
    .transform((v) => v === 'true' || v === '1')
    .default('false'),
  // Rate limit windows (ms)
  AUTH_RATE_WINDOW_MS: z.coerce.number().default(60_000),
  AUTH_RATE_MAX: z.coerce.number().default(10),
  API_RATE_WINDOW_MS: z.coerce.number().default(60_000),
  API_RATE_MAX: z.coerce.number().default(300),
  // Maximum request-body size (bytes) accepted by the /api/v1 proxy on its
  // buffered (non-SSE) forward path. Management-API payloads (client configs,
  // mask uploads, backup-import JSON) are small; this bounds memory against a
  // hostile oversized body. Default 1 MiB. Raise only if a legitimate payload
  // (e.g. a very large backup import) needs it.
  PROXY_MAX_BODY_BYTES: z.coerce.number().int().min(1024).default(1024 * 1024),
  // Separate, larger cap for POST /api/v1/backup/import ONLY: a real backup
  // (client DB + keys) is routinely several MiB and the management daemon
  // itself accepts up to 50 MB — the general 1 MiB cap made any non-trivial
  // backup import fail with 413. Default 64 MiB.
  PROXY_MAX_BACKUP_BODY_BYTES: z.coerce.number().int().min(1024).default(64 * 1024 * 1024),
})

const parsed = envSchema.safeParse(process.env)

if (!parsed.success) {
  console.error('[FATAL] Invalid environment configuration:')
  console.error(parsed.error.flatten().fieldErrors)
  process.exit(1)
}

export const config = parsed.data

// Derived values
export const TRUST_PROXY = config.AIVPN_WEB_TRUST_PROXY
export const IS_SQLITE = !config.DATABASE_URL.startsWith('postgres')
export const RP_ID = new URL(config.ORIGIN).hostname
export const RP_NAME = 'aiVPN Web'

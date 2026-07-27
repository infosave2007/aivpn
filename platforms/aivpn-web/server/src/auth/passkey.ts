import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifiedAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
} from '@simplewebauthn/server'
import { config, RP_ID, RP_NAME } from '../config'
import { randomUUID } from 'node:crypto'

// In-memory single-use store. Registration: keyed by `reg:<userId>`, value is
// the challenge. Authentication: keyed by `auth:<challenge>`, value is the
// userKey the challenge was issued for ('anon' for usernameless logins) —
// keying auth challenges by the challenge itself makes discoverable-credential
// logins work and prevents concurrent anonymous logins racing on a shared key.
// In a multi-process deployment this should be Redis; for single-process it's fine.
const challengeStore = new Map<string, { value: string; expiresAt: number }>()

const CHALLENGE_TTL_MS = 5 * 60 * 1000 // 5 minutes

function storeChallenge(key: string, value: string): void {
  challengeStore.set(key, { value, expiresAt: Date.now() + CHALLENGE_TTL_MS })
}

function consumeChallenge(key: string): string | null {
  const entry = challengeStore.get(key)
  challengeStore.delete(key)
  if (!entry || entry.expiresAt < Date.now()) return null
  return entry.value
}

// ─── Registration ─────────────────────────────────────────────────────────────

export interface ExistingPasskey {
  credential_id: string
  transports: string[] | null
}

export async function getRegistrationOptions(
  userId: number,
  username: string,
  existingPasskeys: ExistingPasskey[],
) {
  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userDisplayName: username,
    attestationType: 'none',
    excludeCredentials: existingPasskeys.map((pk) => ({
      id: pk.credential_id,
      transports: (pk.transports ?? []) as AuthenticatorTransportFuture[],
    })),
    authenticatorSelection: {
      residentKey: 'preferred',
      // 'required': every NEWLY enrolled authenticator must perform user
      // verification (PIN/biometric), not just user presence — this only
      // affects future registrations (an incapable authenticator simply
      // fails to enroll, with no impact on any existing account), so there is
      // no retroactive lockout risk here, unlike the authentication side
      // below.
      userVerification: 'required',
    },
  })

  storeChallenge(`reg:${userId}`, options.challenge)
  return options
}

export async function verifyRegistration(
  userId: number,
  response: RegistrationResponseJSON,
): Promise<VerifiedRegistrationResponse> {
  const expectedChallenge = consumeChallenge(`reg:${userId}`)
  if (!expectedChallenge) throw new Error('No pending registration challenge or challenge expired')

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: config.ORIGIN,
    expectedRPID: RP_ID,
    // Matches authenticatorSelection.userVerification: 'required' above —
    // reject a registration whose authenticator didn't actually perform UV
    // even if it claims to support it.
    requireUserVerification: true,
  })

  if (!verification.verified || !verification.registrationInfo) {
    throw new Error('Passkey registration verification failed')
  }

  return verification
}

// ─── Authentication ───────────────────────────────────────────────────────────

export async function getAuthenticationOptions(
  userKey: string,
  allowedPasskeys?: ExistingPasskey[],
) {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    allowCredentials: allowedPasskeys?.map((pk) => ({
      id: pk.credential_id,
      transports: (pk.transports ?? []) as AuthenticatorTransportFuture[],
    })),
    // Deliberately kept 'preferred' rather than 'required', unlike the
    // registration side above. Existing passkeys were enrolled back when
    // registration also allowed 'preferred', so some already-enrolled
    // authenticators (e.g. a bare FIDO2 security key with no PIN set) may not
    // be capable of user verification at all. 'required' here — for BOTH the
    // ceremony request and requireUserVerification below — would make the
    // browser's WebAuthn call fail outright for those credentials, and for
    // `passkey_only` accounts (db/schema.ts users.passkey_only) that have no
    // password fallback, that is a full account lockout, not just a
    // downgrade. Revisit once there's a way to know/require UV capability at
    // enrollment time for all existing accounts (e.g. a forced re-enrollment
    // migration), or accept the lockout risk as a deliberate policy change.
    userVerification: 'preferred',
  })

  // Key by the challenge value itself; remember which user it was issued for.
  storeChallenge(`auth:${options.challenge}`, userKey)
  return options
}

// Extract the (base64url) challenge echoed back inside clientDataJSON.
// It is only trusted after the single-use store lookup below proves we
// issued it, and after the signature over clientDataJSON verifies.
function extractClientChallenge(response: AuthenticationResponseJSON): string | null {
  try {
    const clientData = JSON.parse(
      Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'),
    ) as { challenge?: unknown }
    return typeof clientData.challenge === 'string' && clientData.challenge.length > 0
      ? clientData.challenge
      : null
  } catch {
    return null
  }
}

export async function verifyAuthentication(
  userKey: string,
  response: AuthenticationResponseJSON,
  passkeyRecord: {
    public_key: string
    counter: number
    transports: string[] | null
    credential_id: string
  },
): Promise<VerifiedAuthenticationResponse> {
  const clientChallenge = extractClientChallenge(response)
  if (!clientChallenge) throw new Error('Malformed authentication response')

  // Single-use: valid only if we issued this exact challenge (present in the
  // store), it is unexpired, and — when it was issued for a specific user —
  // it is presented by that same user. Fails closed on any mismatch.
  const issuedFor = consumeChallenge(`auth:${clientChallenge}`)
  if (issuedFor === null) throw new Error('No pending authentication challenge or challenge expired')
  if (issuedFor !== 'anon' && issuedFor !== userKey) {
    throw new Error('Authentication challenge was issued for a different user')
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: clientChallenge,
    expectedOrigin: config.ORIGIN,
    expectedRPID: RP_ID,
    credential: {
      id: passkeyRecord.credential_id,
      publicKey: Buffer.from(passkeyRecord.public_key, 'base64url'),
      counter: passkeyRecord.counter,
      transports: (passkeyRecord.transports ?? []) as AuthenticatorTransportFuture[],
    },
    // Matches userVerification: 'preferred' in getAuthenticationOptions above
    // — see the comment there for why this isn't 'required' (lockout risk for
    // already-enrolled, possibly non-UV-capable authenticators).
    requireUserVerification: false,
  })

  if (!verification.verified) {
    throw new Error('Passkey authentication verification failed')
  }

  return verification
}

export function newPasskeyId(): string {
  return randomUUID()
}

import { jwtVerify, type JWTVerifyGetKey } from 'jose'

/** ID token должен содержать обязательные поля OIDC, даже если подпись верна. */
export async function verifyIdToken(token: string, keys: JWTVerifyGetKey, issuer: string, audience: string, nonce: string) {
  const { payload } = await jwtVerify(token, keys, {
    issuer, audience, requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'],
  })
  if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 255 ||
      typeof payload.iat !== 'number' || !Number.isFinite(payload.iat) || payload.iat > Date.now() / 1000 + 60 || payload.nonce !== nonce ||
      (payload.azp !== undefined && payload.azp !== audience) ||
      (Array.isArray(payload.aud) && payload.aud.length > 1 && payload.azp !== audience)) {
    throw new Error('Invalid ID token claims')
  }
  return payload as typeof payload & { sub: string; preferred_username?: string; email?: string }
}

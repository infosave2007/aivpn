export interface Discovery {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
}

function secureUrl(value: unknown): URL {
  if (typeof value !== 'string' || value.trim() !== value) throw new Error('Invalid OIDC URL')
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('OIDC requires HTTPS without credentials or fragments')
  }
  return url
}

export function validIssuer(value: string): boolean {
  try { return !secureUrl(value).search } catch { return false }
}

export function parseDiscovery(issuer: string, value: unknown): Discovery {
  if (!validIssuer(issuer) || !value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid OIDC discovery')
  }
  const data = value as Record<string, unknown>
  if (data.issuer !== issuer) throw new Error('OIDC discovery issuer mismatch')
  // Провайдер может размещать endpoints на разных HTTPS-хостах.
  for (const key of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) secureUrl(data[key])
  return {
    issuer, authorization_endpoint: data.authorization_endpoint as string,
    token_endpoint: data.token_endpoint as string, jwks_uri: data.jwks_uri as string,
  }
}

import { expect, test } from 'bun:test'
import { parseDiscovery } from '../src/auth/oidc-discovery'

const issuer = 'https://id.example/realm'
const metadata = {
  issuer,
  authorization_endpoint: 'https://login.example/authorize?tenant=alpha',
  token_endpoint: 'https://tokens.example/token',
  jwks_uri: 'https://keys.example/keys',
}

test('discovery проверяет issuer и HTTPS каждого endpoint', () => {
  expect(parseDiscovery(issuer, metadata)).toEqual(metadata)
  for (const patch of [
    { issuer: 'https://another.example/realm' }, { issuer: undefined },
    { authorization_endpoint: 'http://id.example/auth' },
    { token_endpoint: 'http://id.example/token' },
    { jwks_uri: 'http://id.example/keys' },
    { token_endpoint: 'https://user:secret@id.example/token' },
    { token_endpoint: 'https://id.example/token#fragment' },
    { jwks_uri: '/relative' }, { token_endpoint: null },
  ]) expect(() => parseDiscovery(issuer, { ...metadata, ...patch })).toThrow()
  for (const value of [null, [], 'metadata']) expect(() => parseDiscovery(issuer, value)).toThrow()
})

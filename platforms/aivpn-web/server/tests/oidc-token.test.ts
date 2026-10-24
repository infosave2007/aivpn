import { expect, test } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from 'jose'
import { verifyIdToken } from '../src/auth/oidc-token'

const { privateKey, publicKey } = await generateKeyPair('ES256')
const keys = createLocalJWKSet({ keys: [await exportJWK(publicKey)] })
const now = Math.floor(Date.now() / 1000)
const valid = { iss: 'https://id.example', sub: 'operator-1', aud: 'panel', exp: now + 300, iat: now, nonce: 'random-nonce' }
async function token(claims: Record<string, unknown>) {
  return new SignJWT(claims).setProtectedHeader({ alg: 'ES256' }).sign(privateKey)
}

test('подписанный ID token проверяет обязательные поля и nonce', async () => {
  expect((await verifyIdToken(await token(valid), keys, valid.iss, valid.aud, valid.nonce)).sub).toBe(valid.sub)
  for (const field of ['sub', 'exp', 'iat', 'nonce']) {
    const claims: Record<string, unknown> = { ...valid }
    delete claims[field]
    await expect(verifyIdToken(await token(claims), keys, valid.iss, valid.aud, valid.nonce)).rejects.toBeDefined()
  }
  for (const patch of [{ sub: '' }, { sub: 17 }, { nonce: 'another' }, { exp: now - 1 }, { iat: now + 120 }, { azp: 'another-client' }, { aud: ['panel', 'another'] }]) {
    await expect(verifyIdToken(await token({ ...valid, ...patch }), keys, valid.iss, valid.aud, valid.nonce)).rejects.toBeDefined()
  }
  expect((await verifyIdToken(await token({ ...valid, aud: ['panel', 'another'], azp: 'panel' }), keys, valid.iss, valid.aud, valid.nonce)).sub).toBe(valid.sub)
})

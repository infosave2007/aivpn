import { and, eq, lt } from 'drizzle-orm'

// Нулевой счетчик допустим для ключей, которые не считают подписи.
// Для остальных ключей обновление должно строго увеличивать текущее значение.
export async function claimPasskeyCounter(db: any, passkeys: any, id: string, counter: number): Promise<boolean> {
  const claimed = await db.update(passkeys).set({ counter, last_used_at: new Date() })
    .where(and(eq(passkeys.id, id), counter === 0 ? eq(passkeys.counter, 0) : lt(passkeys.counter, counter)))
    .returning({ id: passkeys.id })
  return claimed.length === 1
}

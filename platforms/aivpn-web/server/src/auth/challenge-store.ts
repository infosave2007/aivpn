export class ChallengeStore {
  private readonly entries = new Map<string, { value: string; expiresAt: number }>()

  constructor(private readonly capacity = 10_000, private readonly ttlMs = 300_000,
    private readonly now = Date.now) {}

  get size(): number { return this.entries.size }

  set(key: string, value: string): void {
    const now = this.now()
    // Порядок вставки совпадает с порядком истечения; очистка не сканирует весь Map.
    for (const [oldKey, entry] of this.entries) {
      if (entry.expiresAt > now) break
      this.entries.delete(oldKey)
    }
    this.entries.delete(key)
    if (this.entries.size >= this.capacity) {
      this.entries.delete(this.entries.keys().next().value!)
    }
    this.entries.set(key, { value, expiresAt: now + this.ttlMs })
  }

  consume(key: string): string | null {
    const entry = this.entries.get(key)
    this.entries.delete(key)
    return entry && entry.expiresAt > this.now() ? entry.value : null
  }
}

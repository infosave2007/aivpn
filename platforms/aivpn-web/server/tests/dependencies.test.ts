import { expect, test } from 'bun:test'
const braces = require('braces')

test('обычные шаблоны продолжают раскрываться', () => {
  expect(braces.expand('file-{1..3}.{ts,js}')).toEqual([
    'file-1.ts', 'file-1.js', 'file-2.ts', 'file-2.js', 'file-3.ts', 'file-3.js',
  ])
})

test('глубокая вложенность отклоняется до переполнения стека', () => {
  for (const [left, right] of [['{', '}'], ['(', ')']]) {
    const pattern = left.repeat(10000) + 'a,b' + right.repeat(10000)
    expect(() => braces(pattern)).toThrow(SyntaxError)
    expect(() => braces.expand(pattern)).toThrow(SyntaxError)
  }
})

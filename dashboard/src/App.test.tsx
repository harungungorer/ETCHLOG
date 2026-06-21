import { describe, it, expect } from 'vitest'

// Smoke test: pure helper to verify the test harness works.
// Full component rendering tests ship with Milestone 7 (in-browser verifier).

function formatLeafIndex(index: number): string {
  return `leaf:${index}`
}

describe('smoke test', () => {
  it('formatLeafIndex returns expected string', () => {
    expect(formatLeafIndex(0)).toBe('leaf:0')
    expect(formatLeafIndex(42)).toBe('leaf:42')
  })

  it('milestone placeholder is correct', () => {
    const milestone = 'milestone 0 — scaffolding only'
    expect(milestone).toContain('scaffolding')
  })
})

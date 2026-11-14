import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

export function verifyProjectionBinding(Projection) {
  const fixture = JSON.parse(readFileSync(new URL('../contracts/feeds/v1/projection-conformance.json', import.meta.url), 'utf8'))
  const bytes = s => new TextEncoder().encode(s)
  const ordinaryError = fn => assert.throws(fn, e => !(e instanceof WebAssembly.RuntimeError))
  assert.equal(fixture.cases.length, 46)
  for (const c of fixture.cases) {
    let p
    if (!c.valid) { ordinaryError(() => new Projection(bytes(c.sourceRaw), bytes(c.selectionRaw), c.origin)); continue }
    try {
      p = new Projection(bytes(c.sourceRaw), bytes(c.selectionRaw), c.origin)
      assert.equal(p.destinationOrigin(), c.origin)
      assert.deepEqual(JSON.parse(p.previewJson()), c.expectedSection, c.id)
      assert.deepEqual(JSON.parse(p.confirm(bytes(c.sourceRaw), c.origin)), c.expectedSection, c.id)
      ordinaryError(() => p.previewJson())
      ordinaryError(() => p.destinationOrigin())
      ordinaryError(() => p.confirm(bytes(c.sourceRaw), c.origin))
    } finally { p?.free() }
  }
  for (const c of fixture.confirmationCases) {
    const p = new Projection(bytes(c.sourceRaw), bytes(c.selectionRaw), c.origin)
    try {
      if (c.valid) JSON.parse(p.confirm(bytes(c.currentSourceRaw), c.confirmOrigin))
      else ordinaryError(() => p.confirm(bytes(c.currentSourceRaw), c.confirmOrigin))
      ordinaryError(() => p.confirm(bytes(c.sourceRaw), c.origin))
    } finally { p.free() }
  }
  const c = fixture.cases[0]
  const s = bytes(c.sourceRaw), choices = bytes(c.selectionRaw)
  const p = new Projection(s, choices, c.origin)
  s.fill(0); choices.fill(0)
  assert.deepEqual(JSON.parse(p.confirm(bytes(c.sourceRaw), c.origin)), c.expectedSection)
  p.free()
  const disposed = new Projection(bytes(c.sourceRaw), bytes(c.selectionRaw), c.origin)
  disposed.dispose(); disposed.dispose()
  ordinaryError(() => disposed.previewJson())
  ordinaryError(() => disposed.confirm(bytes(c.sourceRaw), c.origin))
  disposed.free()
  for (const bad of [new Uint8Array(), new Uint8Array([255]), new Uint8Array(262145)]) {
    ordinaryError(() => new Projection(bad, bytes(c.selectionRaw), c.origin))
    ordinaryError(() => new Projection(bytes(c.sourceRaw), bad, c.origin))
    const consumed = new Projection(bytes(c.sourceRaw), bytes(c.selectionRaw), c.origin)
    ordinaryError(() => consumed.confirm(bad, c.origin))
    ordinaryError(() => consumed.confirm(bytes(c.sourceRaw), c.origin))
    consumed.free()
  }
  return { preparationCases: 46, confirmationCases: 3, lifecycle: 'passed', execution: 'Node; no browser-host consent or transport exercised' }
}

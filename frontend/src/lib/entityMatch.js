// The entity a typed value refers to: exact value first, then case-insensitive; a host wins a tie.
// Shared by the Timeline host field and Details → Add affected system, so "dc01" finds "DC01"
// instead of creating a case-variant duplicate.
export function matchEntity(entities, text) {
  if (!text) return null
  const exact = entities.filter(e => e.value === text)
  const pool  = exact.length ? exact : entities.filter(e => e.value.toLowerCase() === text.toLowerCase())
  return pool.find(e => e.type === 'host') || pool[0] || null
}

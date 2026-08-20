// Minimal line-based diff (LCS). Returns a list of
// { type: 'eq' | 'add' | 'del', line: string }, old -> new.
export function lineDiff(oldText, newText) {
  const a = (oldText ?? '').split('\n')
  const b = (newText ?? '').split('\n')
  const n = a.length, m = b.length

  const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0))
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1])
    }
  }

  const out = []
  let i = 0, j = 0
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({ type: 'eq', line: a[i] }); i++; j++ }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ type: 'del', line: a[i] }); i++ }
    else { out.push({ type: 'add', line: b[j] }); j++ }
  }
  while (i < n) { out.push({ type: 'del', line: a[i] }); i++ }
  while (j < m) { out.push({ type: 'add', line: b[j] }); j++ }
  return out
}

// Display-only: a short name for an audit entry's client. The full User-Agent is
// always available (hover title, expanded entry); nothing is decided on this.
const TOOL = /^(?:fenrir-mcp|curl|python-httpx)\/\S+/i
const BROWSERS = [            // order matters: Edge claims Chrome, Chrome claims Safari
  ['Edge',    /\bEdg(?:e|A|iOS)?\/(\d+)/],
  ['Firefox', /\b(?:Firefox|FxiOS)\/(\d+)/],
  ['Chrome',  /\b(?:Chrome|CriOS)\/(\d+)/],
  ['Safari',  /\bVersion\/(\d+).*\bSafari\//],
]
const OSES = [                // Android claims Linux, iOS claims Mac OS X
  ['Windows', /Windows/], ['Android', /Android/], ['iOS', /iPhone|iPad|iPod/],
  ['macOS', /Macintosh|Mac OS X/], ['ChromeOS', /CrOS/], ['Linux', /Linux|X11/],
]

export function shortClient(ua) {
  if (!ua) return ''
  const tool = ua.match(TOOL)
  if (tool) return tool[0]
  for (const [name, re] of BROWSERS) {
    const m = ua.match(re)
    if (m) {
      const os = OSES.find(([, r]) => r.test(ua))
      return `${name} ${m[1]}${os ? ` (${os[0]})` : ''}`
    }
  }
  return ua.length > 40 ? `${ua.slice(0, 40)}…` : ua
}

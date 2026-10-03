import { useEffect, useRef } from 'react'

// Modal dialog keyboard behaviour (WCAG 2.4.3 / 2.1.2): on open, focus moves to the dialog's
// first form field (else its first control); Tab and Shift+Tab stay inside it; Esc calls
// onEscape; on close, focus returns to whatever had it before (the button that opened it).
// `ref` is the dialog element. onEscape is read fresh on each key press.
const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), '
  + 'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function useDialogFocus(ref, onEscape) {
  const escape = useRef(onEscape)
  escape.current = onEscape

  useEffect(() => {
    const node = ref.current
    if (!node) return undefined
    const opener = document.activeElement
    const focusables = () => [...node.querySelectorAll(FOCUSABLE)].filter(el => el.getClientRects().length > 0)
    if (!node.contains(document.activeElement)) {
      const field = node.querySelector('input:not([disabled]), textarea:not([disabled]), select:not([disabled])')
      ;(field || focusables()[0])?.focus()
    }
    const onKey = (e) => {
      if (e.key === 'Escape') { escape.current?.(); return }
      if (e.key !== 'Tab') return
      const els = focusables()
      if (!els.length) { e.preventDefault(); return }
      const first = els[0]
      const last = els[els.length - 1]
      const inside = node.contains(document.activeElement)
      if (e.shiftKey && (!inside || document.activeElement === first)) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && (!inside || document.activeElement === last)) { e.preventDefault(); first.focus() }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      if (opener && typeof opener.focus === 'function' && document.contains(opener)) opener.focus()
    }
  }, [ref])
}

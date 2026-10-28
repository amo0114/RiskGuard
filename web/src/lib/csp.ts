// Per-response nonce injected by the Go server into <meta name="csp-nonce">. Components that
// must create <style> elements (Base UI, chart colour variables, theme switching) use it so the
// CSP can keep `style-src 'self' 'nonce-…'` without 'unsafe-inline'.
const meta = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')
const value = meta?.content ?? ""

export const cspNonce = value && value !== "__CSP_NONCE__" ? value : undefined

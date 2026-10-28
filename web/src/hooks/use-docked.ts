import * as React from "react"

/**
 * True when detail panels dock beside the list instead of covering it as a drawer. The default
 * fits the sidebar, a readable list and a 28rem panel; wider panels pass a larger breakpoint.
 */
export function useDocked(minWidth = 1280) {
  const query = `(min-width: ${minWidth}px)`
  const subscribe = React.useCallback(
    (onChange: () => void) => {
      const mql = window.matchMedia(query)
      mql.addEventListener("change", onChange)
      return () => mql.removeEventListener("change", onChange)
    },
    [query]
  )
  return React.useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches
  )
}

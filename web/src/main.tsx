import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { CSPProvider } from "@base-ui/react/csp-provider"

import "./index.css"
import App from "./App.tsx"
import { ThemeProvider } from "@/components/theme-provider.tsx"
import { TooltipProvider } from "@/components/ui/tooltip"
import { cspNonce } from "@/lib/csp"
import { StoreProvider } from "@/lib/store"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <CSPProvider nonce={cspNonce}>
      <ThemeProvider>
        <TooltipProvider>
          <StoreProvider>
            <App />
          </StoreProvider>
        </TooltipProvider>
      </ThemeProvider>
    </CSPProvider>
  </StrictMode>
)

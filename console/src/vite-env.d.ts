/// <reference types="vite/client" />

declare global {
  interface Window {
    API_ENDPOINT: string
    // Endpoint the console sends API calls to. Equals API_ENDPOINT unless the
    // server is deployed split (console on intranet, public API on internet).
    CONSOLE_API_ENDPOINT?: string
    IS_INSTALLED: boolean
    VERSION: string
    ROOT_EMAIL: string
    SMTP_BRIDGE_ENABLED: boolean
    SMTP_BRIDGE_DOMAIN: string
    SMTP_BRIDGE_PORT: number
    SMTP_BRIDGE_TLS_MODE: 'off' | 'starttls' | 'implicit'
    OIDC_ENABLED: boolean
    OIDC_BUTTON_LABEL: string
  }
}

export {}

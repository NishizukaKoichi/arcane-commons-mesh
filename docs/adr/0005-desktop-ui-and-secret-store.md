# ADR 0005: Desktop UI and secret store

Status: accepted — 2026-07-26.

The desktop is Tauri 2.11.5 with React 19.2.8 and Vite 8.1.5. Its visual thesis
is a calm operational surface: near-black navigation, warm neutral workspace, and
gold reserved for identity and attention. The application avoids decorative
dashboard-card grids and instead uses dividers, lists, and one primary action.

Japanese is the default language and English navigation is available. Recovery
export gates onboarding. Provider activation gates on a dedicated path.
Destructive deletion requires confirmation and explains 30-day retention.
Governance explicitly states that storage and credit do not alter vote weight.

Identity and vault secrets are assigned to Tauri Stronghold initialized through
the plugin's Argon2 builder and an application-local salt path. The webview
receives no secret value through ordinary status commands. The CSP permits local
assets, IPC, and loopback development control-plane connections only.

The icon is a deterministic repository SVG converted by the Tauri icon generator;
it uses the same three-node mesh geometry and palette as the interface.

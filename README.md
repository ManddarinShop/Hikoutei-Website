# Hikoutei Website

Documentation site (VitePress) + live reliability demo for
[Hikoutei](https://github.com/ManddarinShop/Hikoutei), split out of the
monorepo so docs and demo deploy on their own cadence. The demo server
consumes published `hikoutei` releases from npm (see `demo/server`).

## Layout

- `guide/` — documentation pages; `index.md`, `demo.md` — site roots
- `.vitepress/` — site config and theme
- `demo/frontend` — live demo page; `demo/server` — demo backend;
  `demo/deploy` — VM stack (Caddy + compose + health gate)
- `public/`, `templates/` — static assets and templates

## Commands

```sh
npm ci
npm run docs:dev      # local preview
npm run docs:build    # production build to .vitepress/dist
```

## Deploy

Push to `main` with site paths changed:

- `demo-deploy` — builds docs + demo images, ships to the VM, health-gates
  on `/api/health` reporting `syncMode: sync`
- `drift-watch` (daily cron) — asserts the VM matches the expected shape
  (containers, k3s down, port owners, public sync)
- `docs` — GitHub Pages build (enable Pages → source GitHub Actions)

Required secrets: `DEMO_SSH_HOST`, `DEMO_SSH_USER`, `DEMO_SSH_KEY`,
`DEMO_SA_JSON`, `DEMO_ENV` (same set as the former monorepo workflow).

Dependency bumps arrive as Dependabot PRs; merging one deploys it.

## QA harness

Seeded local-only scenario fuzzing (`qa/`, image `hikoutei-qa`) runs
beside the demo (memory-capped, ephemeral DB, no secrets). Health:
`docker exec deploy-caddy-1 wget -qO- http://qa:3201/api/qa-health`.
Replay a failure with the logged seed via `QA_SEED=<seed>`.

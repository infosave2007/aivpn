# aivpn-web

Web management panel for aivpn. Backend: Hono 4.x on Bun. Frontend: SvelteKit 2.x (static build served by the backend).

## Prerequisites

- [Bun](https://bun.sh) 1.x

## Local Development

```bash
# Install all workspace dependencies
bun install

# Start backend + frontend in watch mode (hot-reload)
bun run dev
```

The backend listens on `http://localhost:8080` by default; the SvelteKit dev server runs on `http://localhost:5173` and proxies API calls to the backend.

## Production Build

```bash
bun install
bun run build   # builds client → client/build/, server bundle → dist/index.js
bun dist/index.js   # serves API + static UI (from client/build)
```

> **Deploy artifact:** `dist/index.js` externalizes the `@node-rs/argon2`
> native addon (bundling it inline breaks the native-binding load), so the
> deploy directory must contain a resolvable `node_modules/` next to `dist/`
> plus the SPA at `client/build/`:
>
> ```bash
> # on the target machine
> deploy/            # dist/index.js + client/build/ + server/package.json
> cd deploy && bun install --production   # materializes node_modules
> bun dist/index.js
> ```
>
> Do **not** rsync the repo's own top-level `node_modules` — it is a bun
> workspace symlink store (`.bun/`) that does not resolve from `dist/`.
> `node_modules` is platform-specific (prebuilt `.node` binary), so run the
> install on the target's OS/arch.
>
> Running from source instead (`bun server/src/index.ts` or root
> `bun run start`) requires `CLIENT_BUILD_DIR=../client/build`, because the
> default resolves relative to the server directory.

## Docker

```bash
# Build image
docker build -t aivpn-web .

# Run (minimal)
docker run -p 8080:8080 \
  -v ./data:/app/data \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET=replace-with-a-long-random-secret \
  aivpn-web
```

To deploy alongside `aivpn-server` use the provided `docker-compose.yml` as an override:

```bash
docker compose -f docker-compose.yml -f platforms/aivpn-web/docker-compose.yml up -d
```

## Environment Variables

| Variable                    | Default                        | Required | Description                                              |
|-----------------------------|--------------------------------|----------|----------------------------------------------------------|
| `DATABASE_URL`              | `file:./data/aivpn-web.db`    | No       | SQLite file path or Postgres URL                         |
| `JWT_SECRET`                | —                              | **Yes**  | Secret used to sign JWT session tokens                   |
| `ORIGIN`                    | —                              | Prod     | Public URL of the panel (e.g. `https://vpn.example.com`) |
| `PORT`                      | `8080`                         | No       | HTTP listen port                                         |
| `UNIX_SOCK`                 | `/run/aivpn/api.sock`          | No       | Path to the aivpn-server management Unix socket          |
| `AIVPN_WEB_ADMIN_PASSWORD`  | —                              | No       | Preset admin password for first-run bootstrap            |
| `AIVPN_WEB_TRUST_PROXY`     | `false`                        | No       | Trust `X-Forwarded-For`/`X-Real-IP` for client IP (rate limits, audit log) |

Copy `.env.example` to `.env` and fill in the required values before running locally.

> **`AIVPN_WEB_TRUST_PROXY` security note:** set it to `true` only when the panel
> sits behind a trusted reverse proxy (e.g. the provided
> `deploy/nginx/aivpn-web.conf`, which **overwrites** the `X-Forwarded-For`
> header with the real client address) — behind a proxy with `false`, every
> visitor resolves to `127.0.0.1` and shares one per-IP rate-limit bucket.
> When the panel is directly reachable, keep `false`: forwarded headers are
> attacker-controlled, and trusting them lets clients spoof their IP to bypass
> per-IP rate limiting and forge audit-log entries.

## First-Run Bootstrap

If no admin account exists in the database, the server creates one automatically on startup. The generated password is printed to stdout once:

```
[aivpn-web] First run — admin account created. Password: <random>
```

Set `AIVPN_WEB_ADMIN_PASSWORD` to choose your own password instead of a generated one.

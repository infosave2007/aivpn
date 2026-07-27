# Stage 1: builder
FROM oven/bun:1 AS builder

WORKDIR /app

# Copy workspace manifests first for layer caching
COPY package.json ./
COPY server/package.json ./server/
COPY client/package.json ./client/

RUN bun install --frozen-lockfile

# Copy source
COPY server/ ./server/
COPY client/ ./client/

# Build SvelteKit static output (the server serves this as the SPA)
RUN bun run --cwd client build

# NOTE: the server runs from source, not a bundle. `bun build` inlines the
# @node-rs/argon2 native addon into dist/index.js, which then fails to load at
# runtime ("Failed to load native binding"). Running src/index.ts directly lets
# Bun resolve the native addon from node_modules normally, so the image boots.

# Stage 2: runtime
# TODO(security): pin with @sha256:<digest> once a digest is chosen to track
# (oven/bun:1-alpine is a floating tag; a digest pin trades that for a
# manual bump on every base-image update).
FROM oven/bun:1-alpine AS runtime

WORKDIR /app

# Copy production deps + server source + package manifest + built SPA,
# owned by the non-root `bun` user (uid=gid=1000 in oven/bun:1-alpine) that
# this image runs as below — root-owned files under /app would otherwise be
# unwritable/unreadable at runtime once USER drops privileges.
COPY --from=builder --chown=bun:bun /app/node_modules ./node_modules
COPY --from=builder --chown=bun:bun /app/server/node_modules ./server/node_modules
COPY --from=builder --chown=bun:bun /app/server/src ./server/src
COPY --from=builder --chown=bun:bun /app/server/package.json ./server/package.json
COPY --from=builder --chown=bun:bun /app/client/build ./client/build

# Persistent data directory (SQLite DB), owned by bun so the app can write
# its DB/WAL files after USER drops root below.
RUN mkdir -p /app/data && chown -R bun:bun /app/data
VOLUME ["/app/data"]

ENV DATABASE_URL=file:./data/aivpn-web.db
ENV PORT=8080
ENV UNIX_SOCK=/run/aivpn/api.sock
# The server runs from /app/server/src, so the default CLIENT_BUILD_DIR
# ("client/build", resolved against the server directory) would point at the
# non-existent /app/server/client/build and the image would serve an API with
# no UI. Point it at the SPA copied to /app/client/build above. The same
# applies to a bare-metal `bun server/src/index.ts` / root `bun run start`
# from a source checkout: export CLIENT_BUILD_DIR=../client/build there too.
ENV CLIENT_BUILD_DIR=../client/build

# Runtime contract — non-root uid/gid 1000, matched against aivpn-server's
# management socket group:
#
# This container runs as the built-in `bun` user (uid=1000, gid=1000 in
# oven/bun:1-alpine — verified via `docker run oven/bun:1-alpine id bun`).
# The panel proxies every /api/v1 request over aivpn-server's management
# Unix socket (UNIX_SOCK, default /run/aivpn/api.sock, bind-mounted from the
# host — see docker-compose.yml). For uid 1000 inside this container to open
# that socket, aivpn-server must be configured with
#   management_socket_group = 1000
# (server.json / CLI flag — see the server-side config docs), which makes
# the server create the socket group-owned by gid 1000 with mode 0660
# instead of the historical 0600-root-only socket. Without that server-side
# setting, this non-root container gets EACCES connecting to the socket.
# If your server's management_socket_group differs from 1000, either change
# it to 1000 or run this container with `--group-add <that gid>` so the
# `bun` user picks up group membership on the socket's actual gid.
USER bun
EXPOSE 8080

CMD ["bun", "server/src/index.ts"]

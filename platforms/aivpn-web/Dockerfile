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

# Copy production deps + server source + package manifest + built SPA.
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/server/node_modules ./server/node_modules
COPY --from=builder /app/server/src ./server/src
COPY --from=builder /app/server/package.json ./server/package.json
COPY --from=builder /app/client/build ./client/build

# Persistent data directory (SQLite DB).
RUN mkdir -p /app/data
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

# Runs as root: the panel must open aivpn-server's management socket
# (/run/aivpn/api.sock), which the server creates mode 0600 owned by root
# with no group/gid option. Dropping to a non-root user here breaks that
# connection until the server side grows a socket-group knob — tracked for a
# future hardening pass (make the socket group-accessible + run this uid in
# that group). See project memory: aivpn-web-nonroot-socket-todo.
EXPOSE 8080

CMD ["bun", "server/src/index.ts"]

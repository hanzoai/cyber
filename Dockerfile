# syntax=docker/dockerfile:1.7

# Stage 1: Build standalone pure TypeScript @hanzo/gui console
FROM --platform=$BUILDPLATFORM node:24-alpine AS web-builder
WORKDIR /src/web
RUN corepack enable && corepack prepare pnpm@10 --activate
COPY web/package.json web/pnpm-workspace.yaml web/tsconfig.json web/gui.config.ts web/index.html ./
COPY web/pnpm-lock.yaml* ./
RUN pnpm install --prefer-offline
COPY web/scripts ./scripts
COPY web/src ./src
RUN pnpm run typecheck && pnpm run test && pnpm run build

# Stage 2: Build zero-dependency Rust cyber-probe scanner
FROM rust:1.86-alpine AS rust-builder
RUN apk add --no-cache musl-dev
WORKDIR /src/rust/cyber-probe
COPY rust/cyber-probe/Cargo.toml ./
COPY rust/cyber-probe/src ./src
RUN RUSTFLAGS="-D warnings" cargo test --offline \
    && RUSTFLAGS="-D warnings" cargo build --release --offline

# Stage 3: Build pure Go Hanzo Cyber control plane & MCP server
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS go-builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
ENV GOTOOLCHAIN=auto \
    GOWORK=off \
    CGO_ENABLED=0
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY pkg ./pkg
COPY deps.go* ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/cyber ./cmd/cyber

# Stage 4: Minimal hardened non-root runtime image
FROM alpine:3.21 AS runtime

ARG VERSION=1.0.0-beta.2
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.title="Hanzo Cyber" \
      org.opencontainers.image.description="Autonomous cyber security control plane, MCP server, zero-dep Rust cyber-probe scanner, and @hanzo/gui operator console" \
      org.opencontainers.image.vendor="Hanzo AI Inc." \
      org.opencontainers.image.url="https://cyber.hanzo.ai" \
      org.opencontainers.image.source="https://github.com/hanzoai/cyber" \
      org.opencontainers.image.documentation="https://github.com/hanzoai/cyber#readme" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 65532 -S cyber \
    && adduser -u 65532 -S -G cyber -h /workspace -s /sbin/nologin cyber \
    && mkdir -p /workspace /opt/hanzo/cyber/web \
    && chown -R 65532:65532 /workspace /opt/hanzo/cyber

COPY --from=go-builder --chmod=0755 /out/cyber /usr/local/bin/cyber
COPY --from=rust-builder --chmod=0755 /src/rust/cyber-probe/target/release/cyber-probe /usr/local/bin/cyber-probe
COPY --from=web-builder --chown=65532:65532 /src/web/dist /opt/hanzo/cyber/web/dist

ENV HANZO_CYBER_DATA_DIR=/workspace \
    HANZO_CYBER_WEB_DIR=/opt/hanzo/cyber/web/dist

WORKDIR /workspace
USER 65532:65532

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["cyber", "doctor", "--data-dir", "/workspace", "--json"]

ENTRYPOINT ["cyber"]
CMD ["serve", "--addr", "0.0.0.0:8787", "--data-dir", "/workspace"]

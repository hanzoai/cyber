# Hanzo Cyber

**Autonomous security operations runtime, MCP server, Rust scanner, and operator console.**  
Live at **[cyber.hanzo.ai](https://cyber.hanzo.ai)** · Source at **[github.com/hanzoai/cyber](https://github.com/hanzoai/cyber)**.

> Use Hanzo Cyber only against systems you own or are explicitly authorized to test.
> Every network probe and tool action is fail-closed on explicit Rules of Engagement scope.

## Architecture

| Component | Stack | Purpose |
| --- | --- | --- |
| Control plane & MCP (`cmd/cyber`, `pkg/control`) | Go (`zap-proto/zip`, `hanzoai/sqlite`, `hanzoai/gen`) | Unified `/v1/cyber/*` REST API, OpenAPI 3.1, `/mcp` stdio/HTTP MCP server, ZAP transport, Enso/Zen operator engine, Hanzo microVM `/v1/sandbox` integration |
| High-speed scanner (`rust/cyber-probe`) | Pure Rust (zero external dependencies) | Concurrent TCP port & banner scanner with fail-closed `--allow-hosts`, secret scanner with strict redaction, deterministic SHA-256 tree verifier |
| Standalone console (`web/`) | Pure TypeScript (`@hanzo/gui`, `@hanzo/ui`, esbuild) | Monochrome operator console for Overview, Mission graph, Findings + verbatim proof verification, Kai approvals + intercept rules, Traffic inspector, Enso/Zen chat, ATT&CK + CoA, Hardening, and System/Doctor |

## Quick start

### 1. Install verified release binaries (macOS / Linux, arm64 / amd64)

```sh
curl -fsSL https://raw.githubusercontent.com/hanzoai/cyber/main/install.sh | bash
```

The installer downloads `SHA256SUMS` first and verifies SHA-256 digests before installing `cyber` and `cyber-probe`.

### 2. Run the control plane & diagnostics

```sh
cyber doctor
cyber serve --addr 127.0.0.1:8787
cyber audit verify --data-dir ~/.hanzo/cyber --org local --engagement <engagement-id>
```

When `./web/dist` (or `HANZO_CYBER_WEB_DIR` / `--web-dir`) is present, `cyber serve` hosts the standalone `@hanzo/gui` monochrome operator console directly at `http://127.0.0.1:8787/`.

Key endpoints exposed by `cyber serve`:

- `GET /` — standalone `@hanzo/gui` operator console (Overview, Mission Graph, Findings, Kai Approvals, Traffic, Chat, ATT&CK, CoA, Hardening, System & Doctor)
- `GET /v1/cyber/health` — runtime liveness, Rust `cyber-probe`, Hanzo Router & microVM sandbox readiness
- `GET /v1/cyber/dashboard` — engagement counts, severity breakdown, verbatim proof rate
- `POST /v1/cyber/engagements/seed-demo` — load the synthetic MDTF tactical enclave lab dataset
- `GET /v1/cyber/tasks/:id/graph` — autonomous reasoning DAG (`goal → intent → finding → kai gate`)
- `POST /v1/cyber/findings/:id/verify` — verbatim substring proof verification against captured HTTP traffic
- `POST /v1/cyber/approvals/:id/decide` — Kai risk-gated human approval decisions
- `POST /v1/cyber/runs` — Kai + Rules-governed execution (native Rust `cyber-probe` or `/v1/sandbox` microVM)
- `GET /v1/cyber/audit` & `POST /v1/cyber/audit/verify` — credential-redacted, SHA-256 hash-chained audit trail & tamper verification
- `POST /v1/cyber/chat` — Enso/Zen operator chat grounded in engagement state
- `GET /.well-known/openapi.json` — live OpenAPI 3.1 specification (30 typed operations)
- `POST /mcp` — native Model Context Protocol surface (30 typed tools)

### 3. Connect an MCP client (stdio)

```json
{
  "mcpServers": {
    "hanzo-cyber": {
      "command": "cyber",
      "args": ["mcp"]
    }
  }
}
```

### 4. Run `cyber-probe` directly

Every `cyber-probe` command emits a deterministic JSON envelope on stdout:

```sh
# Fail-closed TCP port & banner scan (--allow-hosts is mandatory)
cyber-probe ports --target 127.0.0.1 --allow-hosts 127.0.0.0/8 --ports 22,80,443,8787

# Secret & credential scan (strictly redacted previews; raw secrets are never printed)
cyber-probe secrets --path .

# Deterministic SHA-256 directory tree verification
cyber-probe hash --path ./web/dist
```

### 5. Run with Docker (`ghcr.io/hanzoai/cyber`)

```sh
docker run --rm -p 8787:8787 \
  --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -v hanzo-cyber-data:/workspace \
  ghcr.io/hanzoai/cyber:latest
```

The container runs as non-root UID/GID `65532` and bundles `cyber`, `cyber-probe`, and the precompressed `@hanzo/gui` web console at `/opt/hanzo/cyber/web/dist`.

## Safety & governance model

1. **Fail-closed scope enforcement** — Out-of-scope hosts, IPs, and CIDRs are refused before any socket is opened.
2. **Verbatim proof verification** — Findings can be cryptographically bound to captured HTTP exchanges; exact quotes are verified against response headers/body.
3. **Kai risk-gated approvals** — High-risk tool invocations require explicit operator approval (`approved`, `always_allow`, or `denied`) governed by Rules of Engagement intercept guardrails.
4. **Untrusted target data** — Banners, responses, and scanner artifacts are marked untrusted data and strictly redacted for secrets.
5. **Hanzo IAM & microVM isolation** — Production deployments at `https://cyber.hanzo.ai` authenticate via Hanzo IAM (`hanzo.id`), route inference through Enso (`https://api.hanzo.ai`) to Zen models, and isolate active tooling in Hanzo `/v1/sandbox` microVMs.

## Development

```sh
make test              # Run Go vet/tests, Rust cargo test, and TS typecheck + unit tests
make build             # Build bin/cyber, bin/cyber-probe, and web/dist
make release-binaries  # Cross-compile Go binaries + Rust cyber-probe + SHA256SUMS
```

Or run each stack independently:

```sh
GOWORK=off go test ./...
cargo test --manifest-path rust/cyber-probe/Cargo.toml
pnpm --dir web run typecheck && pnpm --dir web run test && pnpm --dir web run build
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

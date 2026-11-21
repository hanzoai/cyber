# Threat playbook: autonomous offensive operations

This note turns a published intrusion chain into defensive requirements. It
deliberately describes techniques generically; no actor name, victim name or
live indicator is carried into the codebase.

## Observed chain

| Phase | Technique | Evidence pattern |
| --- | --- | --- |
| Exposed staging | Open directories on nonstandard ports | Misconfigured Dufs/BaseHTTP services exposing config, scripts and payloads |
| Credential handling | Plaintext secrets in `mode 600` files | SSH, model-relay, proxy and service credentials in a single file with backups |
| Model routing | Relay shims around an agent harness | Local proxies inject reasoning parameters and rewrite model discovery |
| Reconnaissance | Third-party asset search APIs | HMAC-signed queries to a commercial cyberspace search service |
| Proxying | Many exit IPs behind one endpoint | Identity-per-customer credentials, 79 unique exits in a 100-identity sample |
| Initial access | Staged JNDI/LDAP reference chain | In-memory LDAP server returns a `javaNamingReference` to a remote class |
| Validation | Out-of-band DNS callback | Hostname, user and kernel details exfiltrated in a DNS query |
| Post-access | Exchange scripts, LPE, mobile tooling | Withdrawal logic probes, kernel exploits, Android/iOS artifacts |
| Persistence of access | Reverse SSH tunnels + watchdogs | Port forwards restored at boot, sync of operator memory to jump host |

## Control mapping

| Threat | OpenCyber control | Status |
| --- | --- | --- |
| Plaintext credentials on disk | `control/platform.py` stores only KMS key references; sealed env on cloud launch | Covered |
| Unbounded autonomous execution | `control/engine.py` leases, turn/token budgets, wrap-up reserve | Covered |
| Unapproved tool execution | `control/intercept.py` allow/block/ask rules + durable approvals | Covered |
| Tool-call bypass via wrappers | `parse_simple_argv` rejects 27 wrapper binaries and shell metacharacters | Covered |
| Host and target noise | `control/governor.py` per-host token bucket, jitter, 429/503 backoff | Covered |
| Out-of-scope targeting | `policy.enforce_url_scope` on HTTP, browser navigate/requests and replay | Covered |
| Unverified claims | `control/findings.py` verbatim-quote verification against bound traffic | Covered |
| untrusted target text | nonce-framed `frame_untrusted` before it re-enters the model | Covered |
| Exposed admin console | Cloud launch has no default public admin port; console is operator-local behind a bearer token | Covered |
| Upstream telemetry | control state is Hanzo Base or local SQLite; no third-party event sink | Covered |
| IOC / exposure hunting | No dedicated IOC store or certificate/title pivot in the control plane | Gap |
| MITRE ATT&CK coverage view | Events map to tool calls, not yet to ATT&CK techniques | Gap |

## Expansion backlog

1. **IOC collection** — add `indicators` and `sightings` collections to
   `control/store.py`, with typed records (ip, domain, hash, certificate,
   title), confidence and source. Expose `/v1/indicators` and a console tab.
2. **Exposure checks** — a read-only adapter that reports whether an
   engagement's own admin services are publicly reachable and whether any
   workspace file matches credential shapes. Never auto-remediate.
3. **ATT&CK mapping** — attach technique IDs to event kinds and tool names,
   then render a coverage matrix from `/v1/events`.
4. **Retest hardening** — bind each retest to the exact exchange used by the
   original finding and refuse a verdict when the proof body changed.
5. **Proxy hygiene** — flag proxy endpoints that expose many identities and
   require explicit per-identity authorization before use.

## Defensive recommendations

- Remove public access to administrative services; put them behind VPN or an
  allowlist. Treat any unauthenticated directory listing as an incident.
- Rotate every credential that existed in a plaintext file, including relay
  keys, proxy credentials and service tokens.
- Patch internet-facing applications and validate authorization on every
  object reference, not only on the login path.
- Monitor LDAP/JNDI lookups, DNS callbacks to random hostnames, remote script
  downloads, and new reverse tunnels.
- Enforce least privilege on files and use a managed secrets store.
- Restrict model gateways and review their request logs for unexpected model
  endpoints or injected reasoning parameters.
- For managed mobile fleets, enforce device compliance, trusted firmware and
  application allowlists.

## Attribution caution

Broad malware-tag or page-title queries return counts in the thousands. A tag
or title match is a lead, not proof of operator control. Require at least two
independent signals — a unique certificate, a credential file, a distinctive
filename, or a tunnel target — before treating a host as part of a campaign.

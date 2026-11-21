# Cloud launch

The control plane can provision an agentic sandbox in your own Hanzo org from
the console's **Cloud sandbox** page or through the JSON API. Provisioning is a
real platform operation: `POST /v1/platform/run` creates or converges an
Application in `tenant-<org>` derived from the validated IAM identity, and bills
that org. The control plane never guesses or accepts an org in the request body.

## Prerequisites

| Variable | Purpose |
| --- | --- |
| `HANZO_PLATFORM_TOKEN` (or `HANZO_TOKEN` / `HANZO_API_KEY`) | Hanzo IAM bearer token for platform.hanzo.ai |
| `HANZO_PLATFORM_URL` | Default `https://platform.hanzo.ai` |
| `OPENCYBER_CLOUD_IMAGE` | Image to run; default `ghcr.io/hanzoai/opencyber-control:1.0.0-beta.1` |
| `HANZO_PLATFORM_PROJECT` | Platform project; default `default` |
| `OPENCYBER_CLOUD_TOKEN` | Optional fixed control token for launched sandboxes |

The image must expose the control plane on port 8787. `Dockerfile.control` adds
the console layer to the released harness image; build and publish it through
the cluster runner through `platform.hanzo.ai`, not a laptop.

## Launch profiles

| Profile | Behavior |
| --- | --- |
| `agentic-pentest` | Bounded planner/worker engagement, balanced request noise, Hanzo Base persistence |
| `code-review` | Read-only source and dependency review, quiet noise profile |
| `recon` | Passive enumeration and asset discovery, quiet noise profile |

## API

`POST /api/cloud/launch`

```json
{
  "name": "oc-pentest-01",
  "profile": "agentic-pentest",
  "image": "ghcr.io/hanzoai/opencyber-control:1.0.0-beta.1",
  "shape": "auto",
  "env": {}
}
```

The response carries the platform `url`, `status` and a record id. When no
operator token is configured on the control host, a generated control token is
returned **once** as `control_token_once`; it is sent to the platform as a
`secret: true` env entry so it is sealed into KMS and never stored in the
control plane. `HANZO_API_KEY` is handled the same way.

Other routes:

- `GET /api/cloud/config` — platform URL, IAM readiness, profiles, default image
- `GET /api/cloud/launches` — launch records (never secret values)
- `GET /api/cloud/launches/:id/status` — live platform status and last deployments
- `GET /api/cloud/launches/:id/logs` — deployment logs
- `POST /api/cloud/launches/:id/stop` — stop the application

Re-launching the same `name` converges the existing Application in place.

## Accessing the sandbox

Open the returned URL, set the bearer token in **Settings → Operator token**
(the console stores it in browser local storage only), and create an engagement.
All tool calls inside the sandbox still pass the scope check, interception gate
and per-host request governor. Target output remains untrusted data.

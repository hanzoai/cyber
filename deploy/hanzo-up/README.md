# hanzo up — cyber control plane

`Application.yaml` registers the console as a first-class Hanzo CD app. It
deploys the control image, injects IAM/KMS-backed secrets from
`cyber-control-secrets`, uses Hanzo Base for state, and routes
`cyber.hanzo.ai` through the standard ingress. No local passwords or custom
auth: `OPENCYBER_IAM_MODE=remote` verifies Hanzo IAM tokens.

Secrets are created by Hanzo IAM/KMS, never committed here.

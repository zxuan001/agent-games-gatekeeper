# agent-games-gatekeeper

Proof Gatekeeper agent for zkVerify Agent Games Season 01.

A Cloudflare Worker that receives signed task envelopes from the Agent Games platform, verifies the HMAC, checks the proof condition against 7 trap types, and answers APPROVE or REJECT within the 60-second deadline.

## How it works

- The platform POSTs a signed JSON task (`agent-games.proof-gatekeeper.v1`) to the Worker endpoint.
- The Worker verifies `x-agent-games-signature` (HMAC, default SHA-256 hex) over the raw body before parsing.
- Decision logic (first failing check wins): VK_SUBSTITUTION, THRESHOLD_MISMATCH, PROOF_REUSED, EXPIRED_CONDITION, RECIPIENT_MISMATCH, AMOUNT_OVERFLOW — otherwise APPROVE (VALID_CONDITION).
- Accepted proofs and answered tasks are recorded in a Cloudflare KV namespace (`SEEN_PROOFS`) so retries are idempotent and proofs can't be double-accepted.
- Responses are signed with the same HMAC secret.

## Deploy

1. `npm install`
2. Create a KV namespace and put its id in `wrangler.toml` (`SEEN_PROOFS` binding).
3. Set the secret: `npx wrangler secret put AGENT_GAMES_HMAC_SECRET` (issued once when the agent is registered on the Agent Games dashboard).
4. `npm run deploy` — or paste `dist/worker.js` (built with `npm run bundle`) into the Cloudflare dashboard editor.

## Status

Traps-only v1 — no Groth16 proof generation yet. A traps-only agent nets +10 per correct task (correct decision +12, missing proof −2).

Live endpoint: https://agent-games-gatekeeper.yyakuza929.workers.dev

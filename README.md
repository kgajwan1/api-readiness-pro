# API Readiness Pro

A deterministic rule engine that audits API specs (OpenAPI/Swagger, gRPC, or
raw endpoint descriptions) for security and documentation gaps, scored against
OWASP API Top 10 and STRIDE-style categories — with an optional LLM layer
(Gemini, OpenAI, or Claude — bring whichever key you have) for narrative
remediation.

## Why deterministic-first

Most "AI security scanner" demos are an LLM prompt wearing a UI. This one
isn't:

- **The detection logic runs with zero network calls and no API key.** CORS
  wildcards, unauthenticated webhooks, insecure transit, missing auth
  middleware, undocumented parameters — all caught by pattern matching against
  the spec text, in `parseLocalEndpoints`
  ([src/engine/rules.ts](src/engine/rules.ts)).
- **The LLM is opt-in, swappable, and downstream of detection, not part of
  it.** Configure a `GEMINI_API_KEY`, `OPENAI_API_KEY`, or `ANTHROPIC_API_KEY`
  (any one works) and the server calls that provider to write nicer prose
  and code-patch snippets around findings the engine already produced
  (`/api/analyze` in [server.ts](server.ts)). Remove all keys and the scores,
  findings, and a generated remediation report still come back identical —
  see `generateLocalRemediationReport`
  ([src/engine/remediation.ts](src/engine/remediation.ts)).
- **Every score is explainable.** Each finding maps to a concrete rule (e.g.
  "unauthenticated webhook" → Broken Authentication) instead of an opaque
  model judgment.

## 30-second demo

```bash
npm install
npm run dev
```

Open `http://localhost:3000`, then either:

- Click **RUN INTERACTIVE FLOW SIMULATION** to watch the 8-stage pipeline
  (upload → AST route matching → domain extraction → state graph → fuzz
  simulation → risk scoring → AI explanation → dashboard sync) run against the
  built-in payment/refund/webhook sample, or
- Click **NEW ANALYSIS**, pick one of the bundled templates (Stripe-like
  payment gateway, JWT auth core, or a gRPC inventory worker), and run a real
  audit.

No API key required for either path.

## What it checks

| Rule | Category | Severity |
|---|---|---|
| Unauthenticated webhook/payout endpoint | Broken Authentication | Critical |
| Admin/refund route without TLS, auth, or RBAC scope | Security Misconfiguration | Critical |
| No security scheme on any route | Broken Authentication | Critical |
| Duplicate webhook delivery without idempotency check | Double Mutation / Replay | Critical |
| Wildcard CORS (`Access-Control-Allow-Origin: *`) | Misconfiguration | Warning |
| Plaintext HTTP instead of HTTPS | Insecure Transport | Warning |
| Missing parameter descriptions / blank docs | Documentation | Warning |

Each audit produces three scores (Overall Readiness, Security, Documentation)
and a Markdown remediation report with runnable Express/TypeScript patches.

## Architecture

```
server.ts            — Express app; pluggable Gemini/OpenAI/Claude enrichment (/api/analyze)
src/engine/rules.ts        — deterministic rule engine (parseLocalEndpoints)
src/engine/remediation.ts  — Markdown remediation report generator
src/App.tsx           — dashboard UI; imports the engine above
src/data.ts            — sample projects and OpenAPI/gRPC templates used by the demo
sample-apis/           — standalone spec files you can paste into the demo
```

`src/engine/` has no dependency on `server.ts`, React, or any network call —
it's plain TypeScript functions over the spec text.

## Enabling AI-assisted remediation (optional)

Set `GEMINI_API_KEY`, `OPENAI_API_KEY`, and/or `ANTHROPIC_API_KEY` in
`.env.local`, or paste any of them into the **Policy Settings** tab in the UI
— each provider has its own key field, and you pick which one is active for
new analyses. With one configured, `/api/analyze` enriches the same
deterministic result with that provider's generated explanations; without
any key, the app falls back to the offline rule engine automatically.

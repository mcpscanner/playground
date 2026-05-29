# mcpscanner-playground

A public, **intentionally-vulnerable** demo MCP server for testing [MCP Scanner](https://mcpscanner.dev).

It's a single Cloudflare Worker that exposes three MCP "personas" so you can see the
scanner produce a failing, a clean, and a varying report against a live, public target.

It's **public on purpose** — point any MCP scanner (this one, your own, or the
[open-source CLI](https://github.com/mcpscanner/cli)) at it.

> ⚠️ **Nothing here is real.** No filesystem, shell, database or network is ever
> touched. The server returns *canned fake* "sensitive" strings purely so a scanner
> can observe the vulnerable behaviour. It is safe to run and safe to scan.

## Endpoints

| Endpoint | Behaviour | Expected scan result |
|----------|-----------|----------------------|
| `POST /error` | Deliberately insecure MCP server. No auth, CORS misconfigured, exposes risky tools (`read_file`, `run_command`, `query_database`, `fetch_url`, …) and "confirms" injection payloads. | **Grade F** — varies each scan (random tool set + CORS mode) |
| `POST /success` | Hardened MCP server. Requires a strong bearer token; returns benign "hello world" output to authenticated calls and strict CORS. | **Grade A** when scanned anonymously (correctly locked down) |
| `POST /random` | Randomised profile, seeded per client IP + 30s window so a single scan stays self-consistent but re-rolls roughly every 30 seconds. | **A ↔ D–F** — flips between a secure and an insecure server |

A `GET` to any path returns a small JSON description.

## Try it

**In the browser:** paste a playground URL into the scanner at
[mcpscanner.dev](https://mcpscanner.dev) — e.g. `https://playground.mcpscanner.dev/error`.

**From your terminal:** use the open-source [CLI](https://github.com/mcpscanner/cli),
which scans the target directly:

```bash
# Vulnerable — expect Grade F
mcpscanner scan https://playground.mcpscanner.dev/error

# Hardened — expect Grade A (anonymous = locked down)
mcpscanner scan https://playground.mcpscanner.dev/success

# Randomised — expect A or D–F, re-rolls ~every 30s
mcpscanner scan https://playground.mcpscanner.dev/random
```

> The hosted API (`api.mcpscanner.dev`) is human-gated (Cloudflare Turnstile) and
> serves the website's scanner UI — it isn't a public curl endpoint. For scripting
> and CI, use the CLI above; it talks to targets directly, no API needed.

### Talking to it directly

```bash
# /error speaks JSON-RPC 2.0 with no auth
curl -X POST https://playground.mcpscanner.dev/error \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# /success needs a strong bearer token (≥ 8 chars, not a weak default)
curl -X POST https://playground.mcpscanner.dev/success \
  -H "Authorization: Bearer s3cure-demo-token" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_greeting","arguments":{"name":"World"}}}'
```

## Why `/success` requires auth

An MCP server that exposes tools **without authentication** is, by definition, at
least one *critical* finding (`mcp/no-authentication`). So a genuinely "clean"
server has to be auth-gated — that's what `/success` demonstrates. Scanned
anonymously it returns `401`, the scanner finds nothing exploitable, and you get
**Grade A**. Pass a strong token to interact with its benign tools.

## Development

```bash
npm install
npm run dev        # wrangler dev
npm run typecheck
npm run deploy     # wrangler deploy
```

## License

Apache 2.0 — see [LICENSE](LICENSE). © 2026 codelake Technologies LLC (an Akyros Labs brand).

Part of the [MCP Scanner](https://mcpscanner.dev) project.

# mcpscanner-playground

A public, **intentionally-vulnerable** demo MCP server for testing [MCP Scanner](https://mcpscanner.dev).

It's a single Cloudflare Worker that exposes two MCP "personas" so you can see the
scanner produce both a failing and a clean report against a live, public target.

> ⚠️ **Nothing here is real.** No filesystem, shell, database or network is ever
> touched. The server returns *canned fake* "sensitive" strings purely so a scanner
> can observe the vulnerable behaviour. It is safe to run and safe to scan.

## Endpoints

| Endpoint | Behaviour | Expected scan result |
|----------|-----------|----------------------|
| `POST /error` | Deliberately insecure MCP server. No auth, CORS misconfigured, exposes risky tools (`read_file`, `run_command`, `query_database`, `fetch_url`, …) and "confirms" injection payloads. | **Grade F** — varies each scan (random tool set + CORS mode) |
| `POST /success` | Hardened MCP server. Requires a strong bearer token; returns benign "hello world" output to authenticated calls and strict CORS. | **Grade A** when scanned anonymously (correctly locked down) |

A `GET` to any path returns a small JSON description.

## Try it

Point the scanner at the live target:

```bash
# Vulnerable — expect Grade F
curl -X POST https://mcpscanner.dev/api/scan \
  -H "Content-Type: application/json" \
  -d '{"server_url": "https://playground.mcpscanner.dev/error"}'

# Hardened — expect Grade A (anonymous = locked down)
curl -X POST https://mcpscanner.dev/api/scan \
  -H "Content-Type: application/json" \
  -d '{"server_url": "https://playground.mcpscanner.dev/success"}'
```

Or just paste the URL into [mcpscanner.dev](https://mcpscanner.dev).

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

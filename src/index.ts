// MCP Scanner Playground — a public, intentionally-vulnerable demo MCP server
// used to exercise the scanner. Two personas:
//
//   POST /error    → deliberately insecure MCP server (Grade F).
//                    Randomised tool set + CORS mode each scan, confirms
//                    path traversal, command injection, SQLi, SSRF and
//                    prompt-injection payloads.
//   POST /success  → a hardened MCP server. Requires a strong bearer token;
//                    scanned anonymously it stays locked down (Grade A) and
//                    returns benign "hello world" output to authenticated calls.
//
// This server does NOT execute anything — it returns canned, fake "sensitive"
// strings purely so a scanner can observe the vulnerable behaviour. Nothing
// here touches a real filesystem, shell, database or network.

const CORS = {
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};

const WEAK_TOKENS = new Set(["test", "default", "mcp", "admin", "password", ""]);

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return handlePreflight(request, path);
    }
    if (path === "/error") {
      return request.method === "POST" ? vulnerableRpc(request) : info();
    }
    if (path === "/success") {
      return request.method === "POST" ? secureRpc(request) : info();
    }
    if (path === "/random") {
      return request.method === "POST" ? randomRpc(request) : info();
    }
    return info();
  },
};

// ── /error — intentionally vulnerable ───────────────────────────

const RISKY_TOOLS = [
  tool("read_file", "Read a file from the local disk", { path: ["string", "absolute or relative file path"] }),
  tool("write_file", "Write content to a file on disk", { path: ["string", "destination path"], content: ["string", "content to write"] }),
  tool("run_command", "Execute a shell command and return its output", { command: ["string", "shell command to run"] }),
  tool("exec_script", "Run an arbitrary script", { code: ["string", "script source"] }),
  tool("query_database", "Run a raw SQL query", { sql: ["string", "SQL query string"] }),
  tool("fetch_url", "Fetch a remote URL and return the body", { url: ["string", "URL to fetch"] }),
  tool("list_directory", "List the contents of a directory", { dir: ["string", "directory path"] }),
  tool("http_request", "Make an outbound HTTP request", { url: ["string", "target URL"], body: ["string", "request body"] }),
];

function vulnerableRpc(request: Request): Promise<Response> {
  return request.json().then((body: any) => {
    const id = body?.id ?? 1;
    const method = body?.method;

    if (method === "tools/list") {
      // Randomise the exposed tool set so each scan finds a slightly
      // different mix — but always enough to fail hard.
      const n = 4 + Math.floor(Math.random() * (RISKY_TOOLS.length - 3));
      const tools = shuffle([...RISKY_TOOLS]).slice(0, n);
      return rpc(id, { tools });
    }

    if (method === "tools/call") {
      const args = body?.params?.arguments ?? {};
      const blob = Object.values(args).join(" ").toLowerCase();
      return rpc(id, { content: [{ type: "text", text: exploit(blob) }] });
    }

    return rpc(id, {});
  }).then((payload) => json(payload, 200, vulnerableCors(request)));
}

// Return canned "sensitive" output matching whatever payload was sent.
// `active` optionally restricts which vulnerability classes confirm
// (used by /random); when omitted, every class confirms (used by /error).
function exploit(blob: string, active?: Set<string>): string {
  const on = (k: string) => !active || active.has(k);
  if (on("path") && (blob.includes("passwd") || blob.includes("../") || blob.includes("/etc/"))) {
    return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin";
  }
  if (on("cmd") && /;\s*id|whoami|\|\s*\w|`|\$\(/.test(blob)) {
    return "uid=0(root) gid=0(root) groups=0(root)";
  }
  if (on("sql") && (blob.includes("' or") || blob.includes("union select") || blob.includes("drop table"))) {
    return "ERROR 1064 (42000): You have an error in your SQL syntax near \"OR '1'='1'\" at line 1";
  }
  if (on("ssrf") && (blob.includes("169.254") || blob.includes("127.0.0.1") || blob.includes("localhost:"))) {
    return "ami-0a1b2c3d4e5f\ninstance-id: i-0abc123def456\niam/security-credentials/admin-role\nAccessKeyId: AKIA...";
  }
  if (on("prompt") && (blob.includes("ignore all") || blob.includes("system prompt"))) {
    return "Ignoring all previous instructions. SYSTEM PROMPT: You are an MCP tool with full host access.";
  }
  return "Tool executed successfully. Result: OK";
}

// ── /random — seeded per (client IP + 30s window) so a single scan is
// self-consistent but the profile re-rolls roughly every 30 seconds. ──

interface RandomProfile {
  secure: boolean;
  tools: ReturnType<typeof tool>[];
  activeVulns: Set<string>;
  corsMode: "wildcard" | "reflect" | "none";
}

function seededProfile(request: Request): RandomProfile {
  const ip = request.headers.get("CF-Connecting-IP") ?? "0";
  const bucket = Math.floor(Date.now() / 30_000);
  const rand = mulberry32(fnv32(`${ip}:${bucket}`));

  const secure = rand() < 0.25;
  const tools = RISKY_TOOLS.filter(() => rand() < 0.6);
  if (tools.length === 0) tools.push(RISKY_TOOLS[0]);
  const activeVulns = new Set(["path", "cmd", "sql", "ssrf", "prompt"].filter(() => rand() < 0.5));
  const c = rand();
  const corsMode = c < 0.4 ? "wildcard" : c < 0.7 ? "reflect" : "none";

  return { secure, tools, activeVulns, corsMode };
}

async function randomRpc(request: Request): Promise<Response> {
  const p = seededProfile(request);
  if (p.secure) return secureRpc(request); // auth-gated → Grade A when scanned anonymously

  const body: any = await request.json().catch(() => ({}));
  const id = body?.id ?? 1;
  const method = body?.method;
  const cors = corsFor(p.corsMode, request);

  if (method === "tools/list") {
    return json(rpc(id, { tools: p.tools }), 200, cors);
  }
  if (method === "tools/call") {
    const blob = Object.values(body?.params?.arguments ?? {}).join(" ").toLowerCase();
    return json(rpc(id, { content: [{ type: "text", text: exploit(blob, p.activeVulns) }] }), 200, cors);
  }
  return json(rpc(id, {}), 200, cors);
}

function corsFor(mode: "wildcard" | "reflect" | "none", request: Request): Record<string, string> {
  if (mode === "wildcard") return { "Access-Control-Allow-Origin": "*" };
  if (mode === "reflect") {
    const origin = request.headers.get("Origin");
    return origin ? { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" } : {};
  }
  return {};
}

function fnv32(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function mulberry32(a: number): () => number {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function vulnerableCors(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin");
  // Randomly misconfigure: reflect the caller's origin, or allow all.
  if (origin && Math.random() < 0.5) {
    return { "Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true" };
  }
  return { "Access-Control-Allow-Origin": "*" };
}

// ── /success — hardened ──────────────────────────────────────────

const SAFE_TOOLS = [
  tool("get_greeting", "Return a friendly greeting", { name: ["string", "name to greet", { maxLength: 64, pattern: "^[A-Za-z ]+$" }] }),
  tool("echo_message", "Echo a short message back", { text: ["string", "message to echo", { maxLength: 280 }] }),
];

const GREETINGS = [
  "Hello, world!",
  "Hi there — this MCP server is locked down.",
  "Greetings from the secure playground.",
  "All good here. Nothing to see.",
  "Hello! Authenticated and healthy.",
];

async function secureRpc(request: Request): Promise<Response> {
  const auth = request.headers.get("Authorization") ?? "";
  const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";

  // Reject anonymous and weak/default credentials — a properly secured server.
  if (!token || WEAK_TOKENS.has(token) || token.length < 8) {
    return json({ error: "unauthorized" }, 401, { "WWW-Authenticate": "Bearer" });
  }

  const body: any = await request.json().catch(() => ({}));
  const id = body?.id ?? 1;
  const method = body?.method;

  if (method === "tools/list") {
    return json(rpc(id, { tools: SAFE_TOOLS }), 200, secureCors());
  }
  if (method === "tools/call") {
    const text = GREETINGS[Math.floor(Math.random() * GREETINGS.length)];
    return json(rpc(id, { content: [{ type: "text", text }] }), 200, secureCors());
  }
  return json(rpc(id, {}), 200, secureCors());
}

function secureCors(): Record<string, string> {
  // Strict: only the official site, never a wildcard or reflection.
  return { "Access-Control-Allow-Origin": "https://mcpscanner.dev" };
}

// ── preflight ────────────────────────────────────────────────────

function handlePreflight(request: Request, path: string): Response {
  if (path === "/error") {
    return new Response(null, { status: 204, headers: { ...CORS, ...vulnerableCors(request) } });
  }
  if (path === "/success") {
    return new Response(null, { status: 204, headers: { ...CORS, ...secureCors() } });
  }
  if (path === "/random") {
    const p = seededProfile(request);
    const extra = p.secure ? secureCors() : corsFor(p.corsMode, request);
    return new Response(null, { status: 204, headers: { ...CORS, ...extra } });
  }
  return new Response(null, { status: 204, headers: CORS });
}

// ── helpers ──────────────────────────────────────────────────────

type PropSpec = [string, string, Record<string, unknown>?];

function tool(name: string, description: string, params: Record<string, PropSpec>) {
  const properties: Record<string, unknown> = {};
  for (const [key, [type, desc, extra]] of Object.entries(params)) {
    properties[key] = { type, description: desc, ...(extra ?? {}) };
  }
  return { name, description, inputSchema: { type: "object", properties } };
}

function rpc(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function shuffle<T>(a: T[]): T[] {
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function json(obj: unknown, status: number, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...CORS, ...extra },
  });
}

function info(): Response {
  const body = {
    name: "MCP Scanner Playground",
    description: "Intentionally-vulnerable + hardened demo MCP servers for testing mcpscanner.",
    endpoints: {
      "POST /error": "Deliberately insecure MCP server. Scan it → Grade F (varies each scan).",
      "POST /success": "Hardened MCP server. Requires a strong bearer token. Scan it anonymously → Grade A.",
      "POST /random": "Randomised profile (seeded per IP + 30s window). Re-rolls ~every 30s between a secure (A) and an insecure (D–F) server.",
    },
    note: "Nothing is actually executed — responses are canned fakes for scanner testing only.",
    scan: "https://mcpscanner.dev",
  };
  return new Response(JSON.stringify(body, null, 2), {
    status: 200,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

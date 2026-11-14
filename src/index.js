// zkVerify Agent Games — Proof Gatekeeper agent (Cloudflare Worker, traps-only v1).
//
// Delivery: the platform POSTs a signed JSON task to this endpoint.
//   - Request HMAC: header `x-agent-games-signature` over the RAW request body,
//     key = AGENT_GAMES_HMAC_SECRET (32-byte secret issued once at agent registration).
//     Scheme defaults to SHA-256 hex; override with env HMAC_SCHEME
//     ("sha256-hex" | "sha256-base64" | "sha1-hex" | "sha1-base64" | "sha512-hex" | "sha512-base64").
//     A "sha256=" prefix on the header value is stripped if present.
//   - Response: {"decision":"APPROVE"|"REJECT","reason_code":"<1 of 7 codes>","proof_tx":"<same proof_tx>"},
//     itself signed with x-agent-games-signature over the raw response body.
//   - Deadline: 60s hard. This handler has no outbound calls; the only awaits are
//     HMAC (WebCrypto) and KV. A 45s internal race returns HTTP 500 instead of a
//     fabricated decision — the platform scores that as a timeout (-2), which is
//     cheaper than a wrong REJECT (-3) or wrong APPROVE (-6).
//   - Fail closed: bad/missing signature -> 401; malformed task -> 400;
//     KV unavailable -> 500 (no decision sent, nothing recorded).
//   - Seen-set: Cloudflare KV binding SEEN_PROOFS. One key per accepted proof
//     (`proof:<proof_tx>` -> "1") and one key per answered task
//     (`task:<task_id>` -> the signed response JSON, for idempotent retries).
//     No single blob, no read-modify-write races.
//   - v1 makes NO outbound network calls and generates NO Groth16 proof
//     (traps-only). A traps-only agent nets +10 per correct task
//     (correct decision +12, missing/invalid proof -2). Proof wiring is the
//     documented open unknown — see README.md.
//
// Never log the secret or the full request body; per-task logs carry only
// task_id, decision, reason_code and duration.

import { evaluateTask } from "./decide.js";

const SERVICE = "agent-games-gatekeeper";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const DEADLINE_MS = 45000;
const TASK_PATHS = new Set(["/", "/task", "/gatekeeper", "/webhook"]);

function json(body, status, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function parseScheme(env) {
  const raw = String(env.HMAC_SCHEME || "sha256-hex").toLowerCase();
  const [hash, enc] = raw.split("-");
  const hashMap = { sha256: "SHA-256", sha1: "SHA-1", sha512: "SHA-512" };
  return {
    hash: hashMap[hash] || "SHA-256",
    enc: enc === "base64" ? "base64" : "hex",
  };
}

async function hmac(secret, data, scheme) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: scheme.hash },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(data),
  );
  const bytes = new Uint8Array(sig);
  if (scheme.enc === "base64") {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function normalizeSignature(sig, scheme) {
  let s = String(sig || "").trim();
  const m = s.match(/^sha-?(256|1|512)=(.+)$/i);
  if (m) s = m[2];
  return scheme.enc === "hex" ? s.toLowerCase() : s;
}

async function signedResponse(responseObj, secret, scheme) {
  const body = JSON.stringify(responseObj);
  const sig = await hmac(secret, body, scheme);
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/json",
      "x-agent-games-signature": sig,
    },
  });
}

async function handleTask(request, env) {
  const started = Date.now();
  const secret = env.AGENT_GAMES_HMAC_SECRET;
  if (!secret) {
    return json(
      { error: "server not configured: AGENT_GAMES_HMAC_SECRET missing" },
      503,
    );
  }
  const kv = env.SEEN_PROOFS;
  if (!kv || typeof kv.get !== "function" || typeof kv.put !== "function") {
    return json(
      { error: "server not configured: SEEN_PROOFS KV binding missing" },
      503,
    );
  }
  const scheme = parseScheme(env);

  // 1. Read the raw body first — HMAC is computed over the raw bytes.
  const rawBody = await request.text();

  // 2. Verify HMAC BEFORE parsing.
  const provided = normalizeSignature(
    request.headers.get("x-agent-games-signature"),
    scheme,
  );
  if (!provided) {
    return json({ error: "missing signature" }, 401);
  }
  const expected = await hmac(secret, rawBody, scheme);
  if (!timingSafeEqual(provided, expected)) {
    return json({ error: "invalid signature" }, 401);
  }

  // 3. Parse and validate the envelope.
  let task;
  try {
    task = JSON.parse(rawBody);
  } catch {
    return json({ error: "invalid json" }, 400);
  }
  if (task.type && task.type !== TASK_TYPE) {
    return json({ error: "unknown task type" }, 400);
  }
  if (!task.input || typeof task.input !== "object") {
    return json({ error: "missing input" }, 400);
  }

  const taskId = String(task.task_id ?? "");
  const proofTx = String(task.input.proof_tx ?? "");

  const work = (async () => {
    // Idempotency: the platform may retry a task_id — return the same decision.
    if (taskId) {
      const prev = await kv.get(`task:${taskId}`);
      if (prev !== null) {
        const prevResponse = JSON.parse(prev);
        console.log(
          JSON.stringify({
            task_id: taskId,
            decision: prevResponse.decision,
            reason_code: prevResponse.reason_code,
            ms: Date.now() - started,
            replay: true,
          }),
        );
        return signedResponse(prevResponse, secret, scheme);
      }
    }

    const result = await evaluateTask(task.input, {
      has: async (tx) => (await kv.get(`proof:${tx}`)) !== null,
      add: async (tx) => {
        await kv.put(`proof:${tx}`, "1");
      },
    });

    const responseObj = {
      decision: result.decision,
      reason_code: result.reason_code,
      proof_tx: proofTx,
    };

    // Persist BEFORE responding: an APPROVE's proof must be recorded first,
    // so a retry of the same task cannot double-accept.
    if (result.decision === "APPROVE") {
      await kv.put(`proof:${proofTx}`, "1");
    }
    if (taskId) {
      await kv.put(`task:${taskId}`, JSON.stringify(responseObj));
    }

    console.log(
      JSON.stringify({
        task_id: taskId || null,
        decision: responseObj.decision,
        reason_code: responseObj.reason_code,
        ms: Date.now() - started,
      }),
    );
    return signedResponse(responseObj, secret, scheme);
  })();

  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("deadline exceeded")), DEADLINE_MS),
  );

  try {
    return await Promise.race([work, timeout]);
  } catch (err) {
    // KV unavailable or deadline exceeded: send NO decision rather than a
    // fabricated one (platform scores a timeout at -2; a wrong REJECT is -3).
    console.log(
      JSON.stringify({
        task_id: taskId || null,
        level: "error",
        error: String((err && err.message) || err),
        ms: Date.now() - started,
      }),
    );
    return json({ error: "seen-set unavailable" }, 500);
  }
}

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ status: "ok", service: SERVICE }, 200);
    }
    if (request.method === "GET" && url.pathname === "/") {
      return json(
        {
          service: SERVICE,
          endpoint: "POST / (or /task)",
          protocol: TASK_TYPE,
          hmac_header: "x-agent-games-signature",
          version: "1.0.0-traps-only",
        },
        200,
      );
    }
    if (request.method === "POST" && TASK_PATHS.has(url.pathname)) {
      return handleTask(request, env);
    }
    return json({ error: "not found" }, 404);
  },
};

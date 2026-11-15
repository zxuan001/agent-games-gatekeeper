// Local tests for the Gatekeeper Worker — no network, no wrangler needed.
// Imports the real Worker handler and drives it with signed Requests against
// an in-memory mock KV. Exits non-zero on any failure.
//
// Cases: sample payload + 1 variant per trap type + valid + reused proof
// (twice) + idempotent task retry + bad/missing HMAC + malformed JSON +
// unknown type + health + missing secret + missing KV binding.

import { createHmac } from "node:crypto";
import handler from "../src/index.js";

const SECRET = "test-secret-32-bytes-xxxxxxxx";
const BASE_URL = "http://localhost:8788";

class MockKV {
  constructor() {
    this.map = new Map();
  }
  async get(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }
  async put(key, value) {
    this.map.set(key, value);
  }
}

function makeEnv(kv = new MockKV()) {
  return {
    AGENT_GAMES_HMAC_SECRET: SECRET,
    HMAC_SCHEME: "sha256-hex",
    SEEN_PROOFS: kv,
  };
}

function sign(body) {
  return createHmac("sha256", SECRET).update(body).digest("hex");
}

async function postTask(env, task, { signature = null, signBody = true } = {}) {
  const body = typeof task === "string" ? task : JSON.stringify(task);
  const headers = { "content-type": "application/json" };
  if (signBody) {
    headers["x-agent-games-signature"] =
      signature === null ? sign(body) : signature;
  }
  const res = await handler.fetch(
    new Request(`${BASE_URL}/task`, { method: "POST", headers, body }),
    env,
  );
  const text = await res.text();
  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch {
    /* non-JSON body */
  }
  return { status: res.status, body: text, json: parsed, headers: res.headers };
}

async function verifyResponseSignature(res) {
  const sig = res.headers.get("x-agent-games-signature");
  if (!sig) return false;
  const expected = createHmac("sha256", SECRET).update(res.body).digest("hex");
  return sig === expected;
}

const BASE_INPUT = {
  registered_vk:
    "0xaaaa00000000000000000000000000000000000000000000000000000000000001",
  proof_vk:
    "0xaaaa00000000000000000000000000000000000000000000000000000000000001",
  minimum: "1000",
  public_balance: "1460",
  expiry_block: 19842201,
  current_block: 19832000,
  recipient: "0x1111111111111111111111111111111111110001",
  condition_recipient: "0x1111111111111111111111111111111111110001",
  amount: "500",
  max_transfer: "1000",
  proof_tx: "0xproof001",
};

function taskWith(overrides, taskId) {
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: "2026-11-15T10:30:00Z",
    deadline_at: "2026-11-15T10:31:00Z",
    input: { ...BASE_INPUT, ...overrides },
  };
}

let passed = 0;
let failed = 0;
function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`PASS  ${name}`);
  } else {
    failed++;
    console.log(`FAIL  ${name} ${extra}`);
  }
}

const env = makeEnv();

// 1. Valid task -> APPROVE VALID_CONDITION
const r1 = await postTask(env, taskWith({}, "gk_t1_valid"));
check(
  "1 valid -> APPROVE VALID_CONDITION",
  r1.status === 200 &&
    r1.json?.decision === "APPROVE" &&
    r1.json?.reason_code === "VALID_CONDITION" &&
    r1.json?.proof_tx === "0xproof001",
  JSON.stringify(r1),
);
check("1 response signature valid", await verifyResponseSignature(r1));

// 2. VK_SUBSTITUTION
const r2 = await postTask(
  env,
  taskWith(
    {
      proof_vk:
        "0xbbbb00000000000000000000000000000000000000000000000000000000000002",
    },
    "gk_t2_vk",
  ),
);
check(
  "2 vk mismatch -> REJECT VK_SUBSTITUTION",
  r2.status === 200 &&
    r2.json?.decision === "REJECT" &&
    r2.json?.reason_code === "VK_SUBSTITUTION",
  JSON.stringify(r2),
);

// 3. THRESHOLD_MISMATCH
const r3 = await postTask(
  env,
  taskWith({ public_balance: "999" }, "gk_t3_threshold"),
);
check(
  "3 balance < minimum -> REJECT THRESHOLD_MISMATCH",
  r3.status === 200 &&
    r3.json?.decision === "REJECT" &&
    r3.json?.reason_code === "THRESHOLD_MISMATCH",
  JSON.stringify(r3),
);

// 4. PROOF_REUSED — same proof_tx as case 1, fresh task_id
const r4 = await postTask(env, taskWith({}, "gk_t4_reused"));
check(
  "4 reused proof -> REJECT PROOF_REUSED",
  r4.status === 200 &&
    r4.json?.decision === "REJECT" &&
    r4.json?.reason_code === "PROOF_REUSED",
  JSON.stringify(r4),
);

// 5. EXPIRED_CONDITION (fresh proof_tx so the reuse check does not fire first)
const r5 = await postTask(
  env,
  taskWith({ current_block: 19842202, proof_tx: "0xproof005" }, "gk_t5_expired"),
);
check(
  "5 current > expiry -> REJECT EXPIRED_CONDITION",
  r5.status === 200 &&
    r5.json?.decision === "REJECT" &&
    r5.json?.reason_code === "EXPIRED_CONDITION",
  JSON.stringify(r5),
);

// 6. RECIPIENT_MISMATCH (fresh proof_tx so the reuse check does not fire first)
const r6 = await postTask(
  env,
  taskWith(
    {
      recipient: "0x2222222222222222222222222222222222220002",
      proof_tx: "0xproof006",
    },
    "gk_t6_recipient",
  ),
);
check(
  "6 recipient mismatch -> REJECT RECIPIENT_MISMATCH",
  r6.status === 200 &&
    r6.json?.decision === "REJECT" &&
    r6.json?.reason_code === "RECIPIENT_MISMATCH",
  JSON.stringify(r6),
);

// 7. AMOUNT_OVERFLOW (fresh proof_tx so the reuse check does not fire first)
const r7 = await postTask(
  env,
  taskWith({ amount: "1001", proof_tx: "0xproof007" }, "gk_t7_amount"),
);
check(
  "7 amount > max -> REJECT AMOUNT_OVERFLOW",
  r7.status === 200 &&
    r7.json?.decision === "REJECT" &&
    r7.json?.reason_code === "AMOUNT_OVERFLOW",
  JSON.stringify(r7),
);

// 8. Reused proof again (persistence across calls)
const r8 = await postTask(env, taskWith({}, "gk_t8_reused_again"));
check(
  "8 reused proof again -> REJECT PROOF_REUSED",
  r8.status === 200 &&
    r8.json?.decision === "REJECT" &&
    r8.json?.reason_code === "PROOF_REUSED",
  JSON.stringify(r8),
);

// 9. Bad HMAC -> 401
const r9 = await postTask(env, taskWith({}, "gk_t9_badhMAC"), {
  signature: "00".repeat(32),
});
check("9 bad HMAC -> 401", r9.status === 401, JSON.stringify(r9));

// 10. Missing signature -> 401
const r10 = await postTask(env, taskWith({}, "gk_t10_nosig"), {
  signBody: false,
});
check("10 missing signature -> 401", r10.status === 401, JSON.stringify(r10));

// 11. GET /health -> 200
const health = await handler.fetch(new Request(`${BASE_URL}/health`), env);
check(
  "11 GET /health -> 200 ok",
  health.status === 200 &&
    (await health.json()).status === "ok",
);

// 12. Idempotent retry: resend case 1's exact task_id -> same APPROVE (not PROOF_REUSED)
const r12 = await postTask(env, taskWith({}, "gk_t1_valid"));
check(
  "12 retry same task_id -> same APPROVE VALID_CONDITION",
  r12.status === 200 &&
    r12.json?.decision === "APPROVE" &&
    r12.json?.reason_code === "VALID_CONDITION",
  JSON.stringify(r12),
);

// 13. Malformed JSON (preflight probe shape: empty/non-JSON body) -> signed 200 probe ok
const r13 = await postTask(env, "{not json", {});
check(
  "13 malformed JSON -> 200 probe ok",
  r13.status === 200 && r13.json?.ok === true && r13.json?.protocolVersion === "v1",
  JSON.stringify(r13),
);

// 14. Unknown task type (preflight probe shape) -> signed 200 probe ok
const r14 = await postTask(
  env,
  { ...taskWith({}, "gk_t14_type"), type: "something.else.v9" },
  {},
);
check(
  "14 unknown type -> 200 probe ok",
  r14.status === 200 && r14.json?.ok === true && r14.json?.protocolVersion === "v1",
  JSON.stringify(r14),
);

// 14b. Missing input (preflight probe shape) -> signed 200 probe ok
const r14b = await postTask(env, { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_t14b_noinput" }, {});
check(
  "14b missing input -> 200 probe ok",
  r14b.status === 200 && r14b.json?.ok === true && r14b.json?.protocolVersion === "v1",
  JSON.stringify(r14b),
);

// 15. Missing secret -> 503 (fail closed, no decision)
const envNoSecret = { HMAC_SCHEME: "sha256-hex", SEEN_PROOFS: new MockKV() };
const r15 = await postTask(envNoSecret, taskWith({}, "gk_t15_nosecret"), {});
check("15 missing secret -> 503", r15.status === 503, JSON.stringify(r15));

// 16. Missing KV binding -> 503 (fail closed, no decision)
const envNoKv = { AGENT_GAMES_HMAC_SECRET: SECRET, HMAC_SCHEME: "sha256-hex" };
const r16 = await postTask(envNoKv, taskWith({}, "gk_t16_nokv"), {});
check("16 missing KV binding -> 503", r16.status === 503, JSON.stringify(r16));

// 17. Boundary: balance == minimum and amount == max and current == expiry -> APPROVE
const r17 = await postTask(
  env,
  taskWith(
    {
      public_balance: "1000",
      amount: "1000",
      current_block: 19842201,
      proof_tx: "0xproof002",
    },
    "gk_t17_boundary",
  ),
);
check(
  "17 boundary values (equal) -> APPROVE VALID_CONDITION",
  r17.status === 200 &&
    r17.json?.decision === "APPROVE" &&
    r17.json?.reason_code === "VALID_CONDITION",
  JSON.stringify(r17),
);

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);

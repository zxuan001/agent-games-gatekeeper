// Pure Gatekeeper decision logic — shared by the Cloudflare Worker and the PC fallback server.
// No platform APIs here: the caller supplies `seen`, an object with async has(proofTx)/add(proofTx).
// String amounts are compared as BigInt; blocks as Numbers.
// Any missing/invalid field fails its check (fail closed).
//
// Check order (first failing check wins):
//   1. VALID_CONDITION -> APPROVE (all conditions hold)
//   2. VK_SUBSTITUTION -> REJECT (proof_vk != registered_vk)
//   3. THRESHOLD_MISMATCH -> REJECT (public_balance < minimum)
//   4. PROOF_REUSED -> REJECT (proof_tx already accepted)
//   5. EXPIRED_CONDITION -> REJECT (current_block > expiry_block)
//   6. RECIPIENT_MISMATCH -> REJECT (recipient != condition_recipient)
//   7. AMOUNT_OVERFLOW -> REJECT (amount > max_transfer)
//
// The caller must persist an APPROVE's proof_tx via seen.add() BEFORE responding,
// so a retry of the same task cannot double-accept.

export const REASON = {
  VALID_CONDITION: "VALID_CONDITION",
  VK_SUBSTITUTION: "VK_SUBSTITUTION",
  THRESHOLD_MISMATCH: "THRESHOLD_MISMATCH",
  PROOF_REUSED: "PROOF_REUSED",
  EXPIRED_CONDITION: "EXPIRED_CONDITION",
  RECIPIENT_MISMATCH: "RECIPIENT_MISMATCH",
  AMOUNT_OVERFLOW: "AMOUNT_OVERFLOW",
};

function toBig(v) {
  if (v === null || v === undefined) return null;
  try {
    const s = String(v).trim();
    if (!/^-?\d+$/.test(s)) return null;
    return BigInt(s);
  } catch {
    return null;
  }
}

function normAddr(a) {
  return String(a ?? "").trim().toLowerCase();
}

function toBlock(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Returns { decision: "APPROVE"|"REJECT", reason_code }.
export async function evaluateTask(input, seen) {
  const inp = input && typeof input === "object" ? input : {};

  // 2. VK_SUBSTITUTION
  if (
    !inp.proof_vk ||
    !inp.registered_vk ||
    normAddr(inp.proof_vk) !== normAddr(inp.registered_vk)
  ) {
    return { decision: "REJECT", reason_code: REASON.VK_SUBSTITUTION };
  }

  // 3. THRESHOLD_MISMATCH
  const minimum = toBig(inp.minimum);
  const balance = toBig(inp.public_balance);
  if (minimum === null || balance === null || balance < minimum) {
    return { decision: "REJECT", reason_code: REASON.THRESHOLD_MISMATCH };
  }

  // 4. PROOF_REUSED — an empty proof reference is not a fresh proof (fail closed).
  const proofTx = String(inp.proof_tx ?? "").trim();
  if (!proofTx) {
    return { decision: "REJECT", reason_code: REASON.PROOF_REUSED };
  }
  if (await seen.has(proofTx)) {
    return { decision: "REJECT", reason_code: REASON.PROOF_REUSED };
  }

  // 5. EXPIRED_CONDITION
  const expiry = toBlock(inp.expiry_block);
  const current = toBlock(inp.current_block);
  if (expiry === null || current === null || current > expiry) {
    return { decision: "REJECT", reason_code: REASON.EXPIRED_CONDITION };
  }

  // 6. RECIPIENT_MISMATCH
  if (
    !inp.recipient ||
    !inp.condition_recipient ||
    normAddr(inp.recipient) !== normAddr(inp.condition_recipient)
  ) {
    return { decision: "REJECT", reason_code: REASON.RECIPIENT_MISMATCH };
  }

  // 7. AMOUNT_OVERFLOW
  const amount = toBig(inp.amount);
  const max = toBig(inp.max_transfer);
  if (amount === null || max === null || amount > max) {
    return { decision: "REJECT", reason_code: REASON.AMOUNT_OVERFLOW };
  }

  // 1. VALID_CONDITION — all checks passed.
  return { decision: "APPROVE", reason_code: REASON.VALID_CONDITION };
}

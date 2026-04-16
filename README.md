# stellar-soroban-ttl-replay-research
A deep-dive security analysis into persistent storage eviction mechanisms in Soroban (Stellar). This research explores potential replay attack vectors when signed authorization expiration exceeds the storage Time-To-Live (TTL) and discusses the mitigation strategies provided by the Stellar protocol.
# [H-01] DVN Replay Attack via `UsedHash` TTL Expiry — Signed Authorization Can Be Re-Executed After Persistent Storage Eviction

---

> **Severity:** 🔴 HIGH  
> **Target Contract:** `contracts/protocol/stellar/contracts/workers/dvn/src/auth.rs`  
> **Storage File:** `contracts/protocol/stellar/contracts/workers/dvn/src/storage.rs`  
> **Attack Cost:** Zero tokens — requires only a 30-day wait  
> **Recoverability:** Partial — replay window is 30 days wide per signed payload  
> **Chain Exploitable:** ✅ Yes — can be chained with PoC 2 (Nonce DoS) for catastrophic impact

---

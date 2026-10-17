# Forward Patreon Entitlements in AuthZEN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On the catalog route, arks forwards the viewer's Patreon `campaign` and `campaign-tier` entitlements to the platform, filtered and capped, so the platform's composite resolver can entitle a creator for their own campaign exactly as it entitles a patron.

**Architecture:** `pe_claims` (`src/modules/authzen/translate.rs`) builds the claims entity arks sends to the platform's `GetDecision`. Today it forwards `sub`, `iss`, `email` and a sanitised `arkavo_patreon`, and drops `arkavo_entitlements`, which the catalog node (tdf-iroh-s3 `build_authzen_request`) already sends in `subject.properties`. Add a sanitiser next to `sanitize_patreon` and forward its output.

**Tech Stack:** Rust, serde_json, the `log` crate (as `cose_keys.rs` uses).

**Spec:** opentdf-platform fork `docs/superpowers/specs/2026-10-17-composable-entitlement-resolution-design.md` (§4, §5.3, §8), on branch `docs/composable-entitlement-resolution`. Companion plan in the same place: `docs/superpowers/plans/2026-10-17-composable-entitlement-resolution.md`. This plan ships first; it changes no decision until the platform runs the composite.

## Global Constraints

- Forward only `https://patreon.arkavo.com/attr/campaign/value/<digits>` and `https://patreon.arkavo.com/attr/campaign-tier/value/<digits>_<[a-z0-9-]+>`. These are the definitions the platform's `patreon` source owns; identity-core is not PEP-assertable, so nothing else may be forwarded.
- Parse structurally: lowercase first, then require exactly that scheme, host, path shape and value shape. Never test a raw string prefix alone.
- Role-blind: no check on `arkavo_patreon.role` or on any "creator" notion. A creator and a patron with the same entitlements produce the same claims.
- Cap: at most 256 forwarded entries. Over the cap, forward none and `log::warn!` the count. Never truncate silently.
- Forward nothing (omit the key) when no entry survives.
- Keep `sanitize_patreon` and every existing claim unchanged.

## Review Focus

1. **Look-alike hosts and paths:** `https://patreon.arkavo.com.evil/attr/campaign/value/1`, `…/attrs/…`, `…/value/1/2` and `http://` must all be dropped. Pinned in Task 1's first test.
2. **Non-string and mixed-case entries:** a number is dropped; `HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273` is kept, lowercased. Pinned in the same test.
3. **A `campaign-tier` value without `_`:** dropped, because the platform splits on the first `_`. Pinned in the same test.
4. **Exactly 256 vs 257 entries:** 256 forwarded, 257 none. Pinned in `pe_claims_entitlement_cap`.
5. **A PEP that sends `arkavo_entitlements` as a string, not an array:** forward none, no error. Pinned in `pe_claims_omits_entitlements_when_none_allowed`.

---

### Task 1: Forward filtered Patreon entitlements in `pe_claims`

**Files:**
- Modify: `src/modules/authzen/cwt_subject.rs` (next to `sanitize_patreon`)
- Modify: `src/modules/authzen/translate.rs` (`pe_claims`, its NOTE comment, the `use` list)
- Test: the `#[cfg(test)]` module in `src/modules/authzen/translate.rs`

**Interfaces:**
- Produces: `pub fn sanitize_patreon_entitlements(v: &Value) -> Option<Value>` in `cwt_subject.rs`. It returns `Some(Value::Array)` of lowercased, de-duplicated allowed FQNs in input order, and `None` when the input isn't an array, when nothing survives, or when more than `MAX_FORWARDED_ENTITLEMENTS` (`pub const`, 256) survive (with a `log::warn!`).
- `pe_claims` inserts `"arkavo_entitlements"` from `props.get("arkavo_entitlements")` when the sanitiser returns `Some`. Rewrite the NOTE comment: `arkavo_entitlements` is now forwarded, filtered to the Patreon definitions the platform's composite `patreon` source owns (pep_assertable); `email_verified`, `idp`, `arkavo_account_id` and `arkavo_roles` are still dropped.

- [ ] **Step 1: Write the failing tests** in `translate.rs`'s test module, starting from `pe_subject()`:
  - `pe_claims_forwards_patreon_entitlements_only`: set `properties.arkavo_entitlements` to `["https://patreon.arkavo.com/attr/campaign/value/13167240", "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter", "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_tier-555", "tdf:decrypt", "https://arkavo.ai/attr/tdf/value/decrypt", "https://patreon.arkavo.com/attr/arkavo-creator/value/publish", 42, "HTTPS://PATREON.ARKAVO.COM/attr/campaign/value/7237273", "https://patreon.arkavo.com/attr/campaign/value/abc", "https://patreon.arkavo.com/attr/campaign-tier/value/7237273", "https://patreon.arkavo.com.evil/attr/campaign/value/1", "https://patreon.arkavo.com/attrs/campaign/value/1", "https://patreon.arkavo.com/attr/campaign/value/1/2", "http://patreon.arkavo.com/attr/campaign/value/1", "https://patreon.arkavo.com/attr/campaign/value/13167240"]`. Expect `claims["arkavo_entitlements"] == json!(["https://patreon.arkavo.com/attr/campaign/value/13167240", "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_supporter", "https://patreon.arkavo.com/attr/campaign-tier/value/13167240_tier-555", "https://patreon.arkavo.com/attr/campaign/value/7237273"])`.
  - `pe_claims_omits_entitlements_when_none_allowed`: the unmodified `pe_subject()` (`["tdf:decrypt"]`) → `claims.get("arkavo_entitlements").is_none()`. The same holds when the property is the string `"https://patreon.arkavo.com/attr/campaign/value/1"`.
  - `pe_claims_entitlement_cap`: 256 distinct valid campaign FQNs → 256 forwarded; 257 → key absent.
  - `pe_claims_entitlements_are_role_blind`: the same entitlements with `arkavo_patreon.role` `"consumer"` and `"creator"` → equal `arkavo_entitlements` values.
- [ ] **Step 2:** Run `cargo test --lib modules::authzen::translate -- --nocapture`. Expected: FAIL (the key is absent, or `sanitize_patreon_entitlements` is undefined).
- [ ] **Step 3:** Implement `sanitize_patreon_entitlements` and wire it into `pe_claims`.
- [ ] **Step 4:** Run `cargo test --lib modules::authzen`, then `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check`. Expected: all pass, existing `pe_claims_sanitizes_pep_supplied_patreon` and `chain_pe_then_devices_then_env_mismatched_prefix_bind` included.
- [ ] **Step 5: Commit** `feat(authzen): forward filtered Patreon entitlements to the platform`.

## Rollout

Deploy before the platform's shadow step: the platform's `patreon` mode never reads `arkavo_entitlements`, so this is inert until the composite serves. Owner follow-up: add the forwarded `arkavo_entitlements` subject property to draft-arkavo-authzen-cwt-00.

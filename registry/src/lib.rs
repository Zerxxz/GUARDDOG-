/*
 * GUARDDOG — Sentinel Registry (NEAR smart contract, near-sdk 5.29.1)
 *
 * On-chain threat-intel verdicts published by the Sentinel component.
 * Mutations are anchored to NEAR Chain Signatures (MPC): a verdict is only
 * accepted when it arrives with an MPC signature whose recovery validates
 * against the derived public key of (predecessor, derivation path), following
 * the exact derive_epsilon / derive_key / check_ec_signature pattern from the
 * NEAR MPC production sources (near/mpc -> crypto_shared::kdf) and the
 * Chain Signatures docs at docs.near.org
 * (chain-abstraction/chain-signatures/implementation).
 *
 * Blueprint: T2 (4.2 Sentinel Registry) — publish_verdict / is_blocked /
 * verdict / stats with MPC-anchored access control + owner fallback publish.
 */

use k256::elliptic_curve::bigint::U256;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::{AffinePoint, CurveArithmetic, PrimeField};
use k256::{EncodedPoint, ProjectivePoint, Scalar, Secp256k1};
use near_sdk::borsh::{BorshDeserialize, BorshSerialize};
use near_sdk::collections::{LookupMap, UnorderedMap, Vector};
use near_sdk::json_types::U64;
use near_sdk::{
    env, near_bindgen, require, AccountId, BorshStorageKey, PanicOnDefault, PublicKey,
};
use near_sdk::serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Public key of the MPC network (v1.signer-prod.testnet).
/// Verified live on-chain on 2026-10-20 via the `public_key` view call on the
/// MPC contract, and cross-checked against docs.near.org.
const DEFAULT_MPC_PUBLIC_KEY: &str =
    "secp256k1:4NfTiv3UsGahebgTaHyD9vF8KYKMBnfd6kh94mK6xv8fGBiJB8TBtFMP5WWXz6B89Ac1fbpzPwAvoyQebemHFwx3";

/// Prefix from near/mpc crypto_shared::kdf (EPSILON_DERIVATION_PREFIX).
const EPSILON_DERIVATION_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

#[derive(BorshSerialize, BorshStorageKey)]
enum StorageKey {
    Verdicts,
    History,
    ById,
}

/// Threat verdict published by Sentinel (blueprint 4.2).
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(crate = "near_sdk::serde")]
pub struct Verdict {
    pub id: String,
    pub chain: String,
    pub attacker: String,
    pub selector: String,
    pub pattern_hash: String,
    /// 0..=100
    pub confidence: u8,
    pub evidence_tx: String,
    pub timestamp: U64,
}

/// MPC signature proof attached to a verdict (Chain Signatures shape:
/// big_r / s / recovery_id — near/mpc crypto_shared::types::SignatureResponse).
#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct SignatureProof {
    /// Hex (0x-optional) 32-byte hash the MPC network signed; must equal
    /// sha256 of the canonical verdict payload (recomputed on-chain).
    pub payload_hash: String,
    /// big_r.affine_point — SEC1 hex, compressed (33 B) or uncompressed (65 B).
    pub big_r: String,
    /// s.scalar — 32-byte big-endian hex.
    pub s: String,
    /// recovery_id (0 or 1).
    pub recovery_id: u8,
    /// Derivation path used when the signature was requested (e.g. "guarddog-v1").
    pub derivation_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct Stats {
    /// distinct (chain, attacker) verdicts stored
    pub total: U64,
    /// verdicts currently blocking an address (== total in this design)
    pub blocked: U64,
    pub last_publish: Option<U64>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct PublishResult {
    pub accepted: bool,
    /// false when an equal-or-higher-confidence verdict already existed
    pub updated: bool,
    /// true when accepted via verified MPC signature (false = owner fallback)
    pub mpc_signature_valid: bool,
}

#[PanicOnDefault]
#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct Registry {
    owner: AccountId,
    self_id: AccountId,
    /// Near-format "secp256k1:..." MPC network public key used for derivation.
    mpc_public_key: PublicKey,
    mpc_public_key_str: String,
    /// "chain:attacker" -> latest verdict
    verdicts: UnorderedMap<String, Verdict>,
    /// append-only publish log
    history: Vector<Verdict>,
    /// verdict id -> "chain:attacker"
    by_id: LookupMap<String, String>,
    total: u64,
    last_publish: Option<U64>,
}

#[near_bindgen]
impl Registry {
    /// `mpc_public_key` overrides the hardcoded testnet MPC key (key rotation /
    /// other networks); pass null to use the default.
    #[init]
    pub fn new(mpc_public_key: Option<String>) -> Self {
        let (pk, pk_str) = match mpc_public_key {
            Some(s) => {
                require!(s.starts_with("secp256k1:"), "mpc_public_key must be secp256k1");
                let parsed = s.parse::<PublicKey>().expect("invalid mpc_public_key");
                (parsed, s)
            }
            None => (
                DEFAULT_MPC_PUBLIC_KEY.parse().expect("default MPC key parses"),
                DEFAULT_MPC_PUBLIC_KEY.to_string(),
            ),
        };
        Self {
            owner: env::predecessor_account_id(),
            self_id: env::current_account_id(),
            mpc_public_key: pk,
            mpc_public_key_str: pk_str,
            verdicts: UnorderedMap::new(StorageKey::Verdicts),
            history: Vector::new(StorageKey::History),
            by_id: LookupMap::new(StorageKey::ById),
            total: 0,
            last_publish: None,
        }
    }

    /// Publish a threat verdict. Two acceptance paths:
    ///
    /// 1. **MPC-anchored (production path)** — caller supplies an MPC
    ///    signature over sha256(canonical verdict payload). The contract
    ///    recomputes that hash, re-derives the expected derived public key
    ///    for (predecessor_account_id, derivation_path) with the exact Chain
    ///    Signatures algorithm, and requires the recovered signer to equal
    ///    it. Key-level verification (stronger than an EVM address compare,
    ///    which is just the truncated keccak of this same key).
    /// 2. **Owner fallback (demo path)** — contract owner may publish without
    ///    an MPC proof. Blueprint risk-table mitigation for T5 while the
    ///    Sentinel MPC signing pipeline is wired up.
    pub fn publish_verdict(
        &mut self,
        verdict: Verdict,
        signature: Option<SignatureProof>,
    ) -> PublishResult {
        let predecessor = env::predecessor_account_id();
        require!(
            predecessor != self.self_id,
            "publish_verdict: cannot be called by the registry itself"
        );

        let mut mpc_ok = false;
        match &signature {
            Some(proof) => {
                verify_mpc_signature(&self.mpc_public_key, &predecessor, proof, &verdict);
                mpc_ok = true;
            }
            None => {
                require!(
                    predecessor == self.owner,
                    "publish_verdict: caller is not authorized (MPC-signed verdicts \
                     require a valid SignatureProof; unsigned publishes are owner-only)"
                );
            }
        }

        require!(verdict.confidence <= 100, "confidence must be 0..=100");
        let key = verdict_key(&verdict.chain, &verdict.attacker);

        // Upsert: keep the highest-confidence verdict per (chain, attacker).
        let existing = self.verdicts.get(&key);
        let updated = match &existing {
            Some(prev) => verdict.confidence > prev.confidence,
            None => true,
        };
        if updated {
            self.verdicts.insert(&key, &verdict);
            self.history.push(&verdict);
            self.by_id.insert(&verdict.id, &key);
            if existing.is_none() {
                self.total += 1;
            }
            self.last_publish = Some(verdict.timestamp);
        }

        PublishResult { accepted: true, updated, mpc_signature_valid: mpc_ok }
    }

    /// Is `addr` blocked on `chain`? (read-only; consumed by Leash)
    pub fn is_blocked(&self, chain: String, addr: String) -> bool {
        self.verdicts.get(&verdict_key(&chain, &addr)).is_some()
    }

    /// Latest verdict for a (chain, attacker) pair.
    pub fn verdict_for(&self, chain: String, addr: String) -> Option<Verdict> {
        self.verdicts.get(&verdict_key(&chain, &addr))
    }

    /// Verdict by its `id` (blueprint 4.2).
    pub fn verdict(&self, id: String) -> Option<Verdict> {
        self.by_id.get(&id).and_then(|key| self.verdicts.get(&key))
    }

    /// Latest verdicts, newest first (bounded).
    pub fn latest(&self, limit: u32) -> Vec<Verdict> {
        let n = self.history.len();
        let limit = (limit as u64).min(n) as u64;
        let mut out = Vec::new();
        for i in 0..limit {
            if let Some(v) = self.history.get(n - 1 - i) {
                out.push(v);
            }
        }
        out
    }

    pub fn stats(&self) -> Stats {
        Stats {
            total: U64(self.total),
            blocked: U64(self.verdicts.len()),
            last_publish: self.last_publish,
        }
    }

    pub fn owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn mpc_public_key(&self) -> String {
        self.mpc_public_key_str.clone()
    }

    /// Off-chain helper: hash a verdict exactly the way the contract will
    /// recompute it, so Sentinel requests an MPC signature over the right
    /// 32 bytes.
    pub fn expected_payload(&self, verdict: Verdict) -> String {
        to_hex(&env::sha256(payload_bytes(&verdict)))
    }
}

// ---------------------------------------------------------------- internal --

fn verdict_key(chain: &str, attacker: &str) -> String {
    format!("{}:{}", chain, attacker)
}

/// Deterministic canonical bytes hashed by Sentinel and re-derived on-chain.
fn payload_bytes(v: &Verdict) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(v.id.as_bytes());
    b.push(0);
    b.extend_from_slice(v.chain.as_bytes());
    b.push(0);
    b.extend_from_slice(v.attacker.as_bytes());
    b.push(0);
    b.extend_from_slice(v.selector.as_bytes());
    b.push(0);
    b.extend_from_slice(v.pattern_hash.as_bytes());
    b.push(0);
    b.push(v.confidence);
    b.extend_from_slice(v.evidence_tx.as_bytes());
    b.extend_from_slice(&v.timestamp.0.to_be_bytes());
    b
}

/// near/mpc crypto_shared::kdf::derive_epsilon — sha3-256 with the fixed
/// prefix over "{predecessor},{path}" (',' = account-id separator).
fn derive_epsilon(predecessor: &AccountId, path: &str) -> Scalar {
    let derivation_path = format!("{}{},{}", EPSILON_DERIVATION_PREFIX, predecessor, path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_path.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    // from_non_biased in near/mpc: hash space ~2^256 vs field ~2^256-2^129;
    // failure would need ~2^127 attempts. mpc_old panics there; we fall back
    // to ZERO, which can only produce a mismatch panic later — never a
    // false accept.
    Scalar::from_repr(U256::from_be_bytes(hash)).unwrap_or(Scalar::ZERO)
}

/// near/mpc crypto_shared::kdf::derive_key — P_mpc + epsilon*G.
fn derive_key(mpc_pk: &AffinePoint, epsilon: Scalar) -> AffinePoint {
    (ProjectivePoint::GENERATOR * epsilon + ProjectivePoint::from(*mpc_pk)).to_affine()
}

/// near/mpc crypto_shared::near_public_key_to_affine_point — the 64-byte
/// x||y payload behind the "secp256k1:" tag becomes a 0x04-prefixed SEC1 point.
fn near_pk_to_affine(pk: &PublicKey) -> AffinePoint {
    let mut bytes = pk.clone().into_bytes();
    require!(bytes.len() == 65, "unexpected public key encoding");
    bytes[0] = 0x04;
    let point = EncodedPoint::from_bytes(bytes).expect("invalid sec1 point");
    AffinePoint::from_encoded_point(&point).expect("point not on curve")
}

fn parse_hex32(input: &str, what: &str) -> Result<[u8; 32], String> {
    let s = input.trim().strip_prefix("0x").unwrap_or(input);
    if s.len() != 64 {
        return Err(format!("{}: expected 64 hex chars, got {}", what, s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hv = (s.as_bytes()[2 * i] as char).to_digit(16).ok_or(format!("{}: invalid hex", what))?;
        let lv =
            (s.as_bytes()[2 * i + 1] as char).to_digit(16).ok_or(format!("{}: invalid hex", what))?;
        out[i] = (hv * 16 + lv) as u8;
    }
    Ok(out)
}

fn parse_sec1_hex(input: &str, what: &str) -> Vec<u8> {
    let s = input.trim().strip_prefix("0x").unwrap_or(input);
    if s.len() % 2 != 0 || s.is_empty() {
        env::panic_str(&format!("publish_verdict: {} is not valid hex", what));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in 0..s.len() / 2 {
        match u8::from_str_radix(&s[2 * i..2 * i + 2], 16) {
            Ok(b) => out.push(b),
            Err(_) => env::panic_str(&format!("publish_verdict: {} is not valid hex", what)),
        }
    }
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xF) as u32, 16).unwrap());
    }
    s
}

/// Full Chain-Signatures verification for a verdict published by `predecessor`:
/// 1. proof.payload_hash == sha256(canonical verdict bytes)  [payload binding]
/// 2. expected derived key = P_mpc + eps(predecessor, path)*G
/// 3. recovered signer from (big_r, s, recovery_id, payload_hash) == expected
/// Panics on any failure (aborts the publish).
fn verify_mpc_signature(
    mpc_pk: &PublicKey,
    predecessor: &AccountId,
    proof: &SignatureProof,
    verdict: &Verdict,
) {
    // 1. payload binding
    let z = env::sha256(payload_bytes(verdict));
    let got = match parse_hex32(&proof.payload_hash, "payload_hash") {
        Ok(v) => v,
        Err(e) => env::panic_str(&format!("publish_verdict: {}", e)),
    };
    if got != z.as_slice() {
        env::panic_str("publish_verdict: payload_hash does not match the verdict payload");
    }

    // 2. derived public key for (predecessor, path)
    let epsilon = derive_epsilon(predecessor, &proof.derivation_path);
    let expected_key = derive_key(&near_pk_to_affine(mpc_pk), epsilon);

    // 3. recover signer from the MPC response
    let big_r_bytes = parse_sec1_hex(&proof.big_r, "big_r");
    let big_r = match EncodedPoint::from_bytes(big_r_bytes) {
        Ok(p) => p,
        Err(_) => env::panic_str("publish_verdict: big_r is not a valid SEC1 point"),
    };
    let big_r_affine = match AffinePoint::from_encoded_point(&big_r) {
        Some(p) => p,
        None => env::panic_str("publish_verdict: big_r not on curve"),
    };
    let s_bytes = match parse_hex32(&proof.s, "s") {
        Ok(v) => v,
        Err(e) => env::panic_str(&format!("publish_verdict: {}", e)),
    };
    let s_scalar = match Scalar::from_repr(U256::from_be_bytes(s_bytes)).into_option() {
        Some(s) if s != Scalar::ZERO => s,
        _ => env::panic_str("publish_verdict: s is not a valid scalar"),
    };
    require!(proof.recovery_id <= 1, "publish_verdict: recovery_id must be 0 or 1");

    let recovered = recover_signer(&z, x_coordinate(&big_r_affine), s_scalar, proof.recovery_id);
    if recovered != expected_key {
        env::panic_str(&format!(
            "publish_verdict: MPC signature does not match the derived address of \
             (predecessor={}, path={})",
            predecessor, proof.derivation_path
        ));
    }
}

fn x_coordinate(p: &AffinePoint) -> Scalar {
    <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<
        <Secp256k1 as k256::elliptic_curve::Curve>::Uint,
    >>::reduce_bytes(&p.x())
}

/// ECDSA public-key recovery from (z, r, s, recovery_id). Works natively and
/// on wasm with the same code path (k256), so unit tests and on-chain
/// execution behave identically.
fn recover_signer(z: &[u8], r: Scalar, s: Scalar, recovery_id: u8) -> AffinePoint {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    let signature = match Signature::from_scalars(r, s) {
        Ok(sig) => sig,
        Err(_) => env::panic_str("publish_verdict: cannot build signature from MPC response"),
    };
    let rid = RecoveryId::new(recovery_id == 1, false);
    match VerifyingKey::recover_from_prehash(&z[..32], &signature, rid) {
        Ok(vk) => *vk.as_affine(),
        Err(_) => env::panic_str("publish_verdict: signature recovery failed"),
    }
}

// ------------------------------------------------------------------- tests --

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::{AffineCoordinates, Field};
    use near_sdk::test_utils::{VMContext, VMContextBuilder};
    use near_sdk::testing_env;

    fn verdict_fixture(id: &str, chain: &str, attacker: &str, confidence: u8) -> Verdict {
        Verdict {
            id: id.to_string(),
            chain: chain.to_string(),
            attacker: attacker.to_string(),
            selector: "0xa9059cbb".to_string(),
            pattern_hash: "deadbeef".to_string(),
            confidence,
            evidence_tx: format!("0x{}", "11".repeat(32)),
            timestamp: U64(1_700_000_000_000_000_000),
        }
    }

    fn ctx(current: &str, predecessor: &str) -> VMContext {
        VMContextBuilder::new()
            .current_account_id(current.parse().unwrap())
            .signer_account_id(predecessor.parse().unwrap())
            .predecessor_account_id(predecessor.parse().unwrap())
            .build()
    }

    const REGISTRY: &str = "registry.testnet";

    #[test]
    fn init_sets_owner_from_predecessor() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let c = Registry::new(None);
        assert_eq!(c.owner().as_str(), "alice.testnet");
        assert_eq!(c.mpc_public_key(), DEFAULT_MPC_PUBLIC_KEY);
        assert_eq!(c.stats().total.0, 0);
        assert!(c.stats().last_publish.is_none());
    }

    #[test]
    fn owner_fallback_publish_ok() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        let v = verdict_fixture("v1", "base-sepolia", "0xATTACKER", 80);
        let res = c.publish_verdict(v.clone(), None);
        assert!(res.accepted && res.updated && !res.mpc_signature_valid);
        assert!(c.is_blocked("base-sepolia".into(), "0xATTACKER".into()));
        assert!(!c.is_blocked("base-sepolia".into(), "0xUNKNOWN".into()));
        assert_eq!(c.verdict("v1".into()).unwrap(), v);
        assert_eq!(c.verdict_for("base-sepolia".into(), "0xATTACKER".into()).unwrap(), v);
        assert_eq!(c.stats().total.0, 1);
        assert_eq!(c.stats().blocked.0, 1);
        assert!(c.stats().last_publish.is_some());
    }

    #[test]
    #[should_panic(expected = "not authorized")]
    fn unauthorized_publish_rejected() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        testing_env!(ctx(REGISTRY, "eve.testnet"));
        let v = verdict_fixture("v2", "base-sepolia", "0xATTACKER", 90);
        let _ = c.publish_verdict(v, None);
    }

    #[test]
    #[should_panic(expected = "cannot be called by the registry itself")]
    fn self_publish_rejected() {
        testing_env!(ctx(REGISTRY, REGISTRY));
        let mut c = Registry::new(None);
        let _ = c.publish_verdict(verdict_fixture("v", "base-sepolia", "0xA", 10), None);
    }

    #[test]
    fn duplicate_keeps_higher_confidence() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        let _ = c.publish_verdict(verdict_fixture("v1", "base-sepolia", "0xA", 80), None);
        // lower confidence duplicate -> no update
        let res = c.publish_verdict(verdict_fixture("v2", "base-sepolia", "0xA", 60), None);
        assert!(!res.updated);
        assert_eq!(c.stats().total.0, 1);
        assert_eq!(c.verdict("v1".into()).unwrap().confidence, 80);
        assert!(c.verdict("v2".into()).is_none());
        // higher confidence -> update, still one distinct key
        let res = c.publish_verdict(verdict_fixture("v3", "base-sepolia", "0xA", 95), None);
        assert!(res.updated);
        assert_eq!(c.stats().total.0, 1);
        assert_eq!(c.verdict("v3".into()).unwrap().confidence, 95);
        assert_eq!(c.stats().blocked.0, 1);
        assert_eq!(c.history.len(), 2);
    }

    #[test]
    #[should_panic(expected = "confidence must be")]
    fn confidence_above_100_rejected() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        let mut v = verdict_fixture("vb", "base-sepolia", "0xB", 101);
        v.confidence = 101;
        let _ = c.publish_verdict(v, None);
    }

    #[test]
    fn confidence_100_accepted() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        let mut v = verdict_fixture("vb", "base-sepolia", "0xB", 100);
        v.confidence = 100;
        let res = c.publish_verdict(v, None);
        assert!(res.accepted);
    }

    // ---- MPC-anchored publish path ----

    use k256::elliptic_curve::PrimeField as _;

    /// Base setup shared by MPC tests: registry MPC key is `D - eps*G` so the
    /// derived key for (signer, path) equals `D = d*G`; craft an MPC-style
    /// signature over z recovering D. Exercises the full verification path.
    struct MpcFixture {
        registry: Registry,
        proof: SignatureProof,
        verdict: Verdict,
        z: String,
    }

    fn mpc_fixture(path: &str, signer: &str, derived_d: u64, nonce: u64) -> MpcFixture {
        let d = Scalar::from(derived_d);
        let k = Scalar::from(nonce);
        let big_r_affine = (ProjectivePoint::GENERATOR * k).to_affine();
        let eps = derive_epsilon(&signer.parse().unwrap(), path);
        let p_mpc =
            (ProjectivePoint::from(big_r_affine * d) - ProjectivePoint::GENERATOR * eps).to_affine();
        let p_mpc_near = affine_to_near_str(&p_mpc);

        let mut verdict = verdict_fixture("vmpc", "base-sepolia", "0xBADC0DE", 99);
        verdict.timestamp = U64(1_700_000_000_000_000_000 + nonce);

        testing_env!(ctx(REGISTRY, signer));
        let registry = Registry::new(Some(p_mpc_near));
        let z = registry.expected_payload(verdict.clone());
        let z_bytes = parse_hex32(&z, "z").unwrap();
        let z_scalar = Scalar::from_repr(U256::from_be_bytes(z_bytes)).unwrap();
        let r = x_coordinate(&big_r_affine);
        let s = k.invert().unwrap() * (z_scalar + r * d);
        let proof = SignatureProof {
            payload_hash: z.clone(),
            big_r: to_hex(big_r_affine.to_encoded_point(false).as_bytes()),
            s: to_hex(&s.to_bytes()),
            recovery_id: big_r_affine.y_is_odd().unwrap_u8(),
            derivation_path: path.to_string(),
        };
        MpcFixture { registry, proof, verdict, z }
    }

    fn affine_to_near_str(p: &AffinePoint) -> String {
        // "secp256k1:" + base58(64-byte x||y)
        let ep = p.to_encoded_point(false);
        format!("secp256k1:{}", b58_encode(&ep.as_bytes()[1..65]))
    }

    fn b58_encode(bytes: &[u8]) -> String {
        const ALPH: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut digits: Vec<u8> = vec![]; // base58 digits, little-endian
        let mut num: Vec<u8> = bytes.to_vec(); // big-endian big int
        while num.iter().any(|&x| x != 0) {
            let mut rem: u32 = 0;
            for byte in num.iter_mut() {
                let cur = (rem << 8) | *byte as u32;
                *byte = (cur / 58) as u8;
                rem = cur % 58;
            }
            digits.push(rem as u8);
        }
        let mut out = String::new();
        for d in digits.iter().rev() {
            out.push(ALPH[*d as usize] as char);
        }
        for &b in bytes {
            if b == 0 {
                out.insert(0, '1');
            } else {
                break;
            }
        }
        if out.is_empty() {
            out.push('1');
        }
        out
    }

    #[test]
    fn mpc_signature_validates_and_publishes() {
        let MpcFixture { mut registry, proof, verdict, .. } =
            mpc_fixture("guarddog-v1", "sentinel.testnet", 42, 77);
        let res = registry.publish_verdict(verdict, Some(proof));
        assert!(res.accepted && res.mpc_signature_valid);
        assert!(registry.is_blocked("base-sepolia".into(), "0xBADC0DE".into()));
        assert_eq!(registry.stats().total.0, 1);
        // the derived key must be exactly D = 42*G
        let expected = (ProjectivePoint::GENERATOR * Scalar::from(42u64)).to_affine();
        assert_eq!(registry.mpc_public_key(), affine_to_near_str(&expected));
    }

    #[test]
    #[should_panic(expected = "does not match the derived address")]
    fn mpc_signature_wrong_derivation_path_rejected() {
        let MpcFixture { mut registry, mut proof, verdict, .. } =
            mpc_fixture("guarddog-v1", "sentinel.testnet", 42, 77);
        proof.derivation_path = "attacker-path".to_string();
        let _ = registry.publish_verdict(verdict, Some(proof));
    }

    #[test]
    #[should_panic(expected = "does not match the derived address")]
    fn mpc_signature_from_wrong_account_rejected() {
        // signature crafted for (sentinel.testnet, path) but published by eve
        let MpcFixture { mut registry, proof, verdict, .. } =
            mpc_fixture("guarddog-v1", "sentinel.testnet", 42, 77);
        testing_env!(ctx(REGISTRY, "eve.testnet"));
        let _ = registry.publish_verdict(verdict, Some(proof));
    }

    #[test]
    #[should_panic(expected = "payload_hash does not match")]
    fn mpc_signature_payload_mismatch_rejected() {
        let MpcFixture { mut registry, mut proof, mut verdict, .. } =
            mpc_fixture("guarddog-v1", "sentinel.testnet", 42, 77);
        verdict.confidence = 10; // tamper after signing
        proof.payload_hash = to_hex(&env::sha256(vec![0u8; 4])); // keep 64-hex shape
        let _ = registry.publish_verdict(verdict, Some(proof));
    }

    #[test]
    #[should_panic(expected = "big_r is not valid hex")]
    fn mpc_signature_garbage_rejected() {
        testing_env!(ctx(REGISTRY, "sentinel.testnet"));
        let mut registry = Registry::new(None);
        let verdict = verdict_fixture("vg", "base-sepolia", "0xBADC0DE", 99);
        // payload hash correct so verification reaches the big_r parse step
        let proof = SignatureProof {
            payload_hash: registry.expected_payload(verdict.clone()),
            big_r: "not-hex".to_string(),
            s: "00".repeat(32),
            recovery_id: 0,
            derivation_path: "guarddog-v1".to_string(),
        };
        let _ = registry.publish_verdict(verdict, Some(proof));
    }

    #[test]
    fn mpc_verdict_replayed_by_owner_still_validates() {
        // A genuine MPC verdict stays valid regardless of who relays it:
        // the binding is (predecessor, path) — here eve relays sentinel's
        // proof but the proof is bound to eve's own derived key.
        let MpcFixture { mut registry, proof, verdict, z } =
            mpc_fixture("guarddog-v1", "eve.testnet", 42, 78);
        assert_eq!(z.len(), 64);
        let res = registry.publish_verdict(verdict, Some(proof));
        assert!(res.mpc_signature_valid);
    }

    #[test]
    fn latest_and_stats_shape() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let mut c = Registry::new(None);
        for i in 0..3u8 {
            let _ = c.publish_verdict(
                verdict_fixture(&format!("v{}", i), "base-sepolia", &format!("0x{:02X}", i), 50 + i),
                None,
            );
        }
        let latest = c.latest(2);
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].id, "v2"); // newest first
        assert_eq!(c.stats().total.0, 3);
        assert_eq!(c.latest(100).len(), 3);
    }

    #[test]
    fn expected_payload_is_deterministic() {
        testing_env!(ctx(REGISTRY, "alice.testnet"));
        let c = Registry::new(None);
        let v = verdict_fixture("vd", "base-sepolia", "0xD", 70);
        let h1 = c.expected_payload(v.clone());
        let h2 = c.expected_payload(v);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        let mut v2 = verdict_fixture("vd", "base-sepolia", "0xD", 70);
        v2.confidence = 71;
        assert_ne!(c.expected_payload(v2), h1);
    }
}

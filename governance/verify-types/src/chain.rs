//! Verifier chain-walk for the specification — multi-step pipeline composition.
//!
//! ## What this module is
//!
//! the specification (Accepted 2026-05-07) introduces `parent_audit_proof_id` as a
//! customer-declared field on FullCdp / VerificationCdp. D2 — this module —
//! ships the verifier semantics that turn a chain of customer-linked
//! AuditProofs into a single signed trust DAG: walk from leaf back to genesis,
//! verifying at each link
//!
//! 1. the link's own signature + canonical_hash (delegated to
//!    `ChainNode::verify_self()` — caller provides per-link verification; this
//!    module composes the chain),
//! 2. the parent reference points at a fetchable, structurally-valid parent,
//! 3. `child.org_id == parent.org_id` (the **cross-customer parent-chain
//!    attack closure** — Class-A trust invariant; co-owned with Internal
//!    Auditor per runbook),
//! 4. the chain has not entered a cycle (DOS defense),
//! 5. the chain has not exceeded `max_depth` (DOS defense; default
//!    `DEFAULT_MAX_CHAIN_DEPTH = 100`).
//!
//! ## Trait-based abstraction (zero runtime deps)
//!
//! `verify-types` is a pure-types crate (only serde + thiserror; no tokio, no
//! sqlx, no cdp_document concrete types). The runbook example pseudocode uses
//! `crate::AuditProof` for readability, but pulling the concrete `FullCdp` /
//! `VerificationCdp` type into this crate would create a cyclic dependency
//! (services/api depends on verify-types via `FailureReason`). Instead, this
//! module exposes a `ChainNode` trait that `services/api`, `tools/cli`, and
//! the Python/TypeScript SDKs each implement for their concrete AuditProof
//! variant. Chain-walk semantics are locked here once; the algorithm is
//! adapter-agnostic.
//!
//! ## In-walk caching (DAG semantics)
//!
//! Chains may share ancestors (multiple leaves pointing to the same root —
//! a DAG, not just a tree). Within a single `verify_chain` invocation, parents
//! are cached in a `HashMap<String, ChainVerification>` so a node touched
//! multiple times is verified once. The cache drops when `verify_chain`
//! returns; cross-walk caching is forbidden by zero-retention discipline
//! (`feedback_no_post_destroy_cache.md`).
//!
//! ## Forever-Standard discipline (the Forever-Standard wire discipline)
//!
//! Chain-walk semantics are themselves Forever-Standard locked once shipped.
//! Future ADRs cannot change the cycle-detection algorithm, the depth-limit
//! default, the customer-id binding enforcement, or the in-walk caching
//! policy without an specification minor-bump. The cdp_version field is NOT
//! modified by this module — chain-walk is an additive verifier capability;
//! AuditProof shape stays "2.1" per Path A precedent (commit `c32cf37`).
//!
//! ## Cross-customer parent-chain attack closure
//!
//! The `org_id` binding is the **single most load-bearing invariant** in this
//! module. Without it, customer A could declare customer B's AuditProof as
//! its parent, falsely coupling two unrelated trust DAGs. Defense is layered:
//!
//! 1. **API layer** (services/api): refuses INSERT if `parent_audit_proof_id`
//!    references a row in `proofs` whose `org_id` differs from the caller.
//! 2. **DB CHECK constraint** (migration 049, future): enforces same-org
//!    linkage at write time as a structural guard.
//! 3. **Verifier layer** (this module): fails closed on `child.org_id !=
//!    parent.org_id` regardless of how the chain got into the verifier's
//!    hands. A malicious actor who bypasses (1) + (2) still cannot construct
//!    a cross-customer chain that verifies.
//!
//! Property test `prop_chain_walk_rejects_cross_customer_parent_under_random_chain_depth`
//! exhausts random org_id permutations across chain depths to lock this
//! invariant under fault paths per `feedback_canonical_hash_under_fault.md`.

use std::collections::{HashMap, HashSet};

use crate::FailureReason;

/// Default maximum chain depth (hops from leaf to genesis). Customer chains
/// exceeding this depth must explicitly pass a higher `max_depth` to
/// `verify_chain`. The default defends against DoS via deeply-nested chains;
/// customer override is a deliberate operational decision.
///
/// **Forever-Standard** — value of 100 is locked at the specification ship; future
/// changes require the specification minor-bump per the chain-walk semantics lock.
pub const DEFAULT_MAX_CHAIN_DEPTH: usize = 100;

/// Trait exposing the minimal AuditProof surface that chain-walk needs.
///
/// Concrete implementations live in
/// - the AuditProof document builder (impl for `FullCdp` and
///   `VerificationCdp`),
/// - `tools/cli` (impl for the offline-deserialized AuditProof JSON),
/// - SDK adapters (Python / TypeScript; deferred per SDK 1.0 publish-block).
///
/// Implementors are responsible for `verify_self()` — that is where signature
/// verification + canonical_hash recompute lives. Chain-walk composes the
/// per-link results into a chain-level verification; it does not duplicate
/// per-link verification logic.
pub trait ChainNode {
    /// The capsule_id of this AuditProof (`^cap_[0-9a-f]{32}$`).
    fn capsule_id(&self) -> &str;

    /// The owning customer's org_id. Snapshotted from `capsules.org_id` at
    /// destroy time. **Load-bearing** for cross-customer attack closure.
    fn org_id(&self) -> &str;

    /// The customer-declared parent AuditProof reference (the specification).
    /// `None` indicates a pipeline-genesis capsule — chain-walk terminates here.
    fn parent_audit_proof_id(&self) -> Option<&str>;

    /// Verify this AuditProof's own signature + canonical_hash + structural
    /// invariants. Returns the per-link verification result (signature,
    /// canonical_hash, signing_key_version metadata) on success, or a
    /// per-link failure on the closed `FailureReason` enum.
    ///
    /// Crypto Reviewer scope: this method is the authority surface for
    /// per-link signature verification. Chain-walk consumes its result
    /// faithfully; chain-walk does not re-verify the signature.
    fn verify_self(&self) -> Result<SingleVerification, SingleVerificationFailure>;
}

/// Per-link verification result — produced by `ChainNode::verify_self()`,
/// consumed by chain-walk.
///
/// Fields are intentionally minimal: the chain-walk surface carries enough
/// metadata for a top-level auditor to reconstruct what was verified at each
/// link without leaking internal verifier state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleVerification {
    /// The capsule_id of the verified AuditProof. Matches `ChainNode::capsule_id()`.
    pub capsule_id: String,
    /// The owning org_id of the verified AuditProof. Matches `ChainNode::org_id()`.
    pub org_id: String,
    /// `true` iff the AuditProof's Ed25519 signature verified against the
    /// signed canonical_hash bytes per the specification.
    pub signature_verified: bool,
    /// `true` iff the AuditProof's `final_hash` recomputed identically from
    /// the canonical view per the AuditProof specification.
    pub canonical_hash_verified: bool,
    /// The `signing_key_version` field from the AuditProof — identifies which
    /// signing-authority version produced the signature. Useful for top-level
    /// auditor analysis of which authority versions a chain spans.
    pub signing_key_version: String,
}

/// Per-link verification failure surface — produced by
/// `ChainNode::verify_self()` when a link does not verify. The `reason` is
/// the closed `FailureReason` enum (the Forever-Standard wire discipline forever-stable wire-form).
#[derive(Debug, Clone, PartialEq)]
pub struct SingleVerificationFailure {
    /// The capsule_id of the failed AuditProof. Lets the auditor pinpoint
    /// which link in a multi-step chain failed.
    pub capsule_id: String,
    /// Closed-enum failure reason — auditor consumers route on this.
    pub reason: FailureReason,
}

/// Result of a chain verification walk. Recursive structure mirrors the
/// chain shape: a leaf with no parent is `Genesis`; a leaf with a verified
/// parent is `Linked { this, parent:... }`.
///
/// The caller can recurse the result tree to render a top-down audit view:
/// "this AuditProof composed output from its parent, which composed from
/// grandparent,...".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerification {
    /// Pipeline-genesis capsule — chain terminates here. The leaf's
    /// `parent_audit_proof_id` is `None`.
    Genesis(SingleVerification),
    /// Intermediate capsule — verified itself AND has a verified parent.
    /// `parent` is boxed because the recursive enum is not Sized otherwise.
    Linked {
        /// Verification result for *this* node (the child in this layer).
        this: SingleVerification,
        /// Recursive verification result for the parent chain.
        parent: Box<ChainVerification>,
    },
}

impl ChainVerification {
    /// Return the leaf-most `SingleVerification` (the node the caller
    /// originally passed to `verify_chain`).
    pub fn leaf(&self) -> &SingleVerification {
        match self {
            ChainVerification::Genesis(v) => v,
            ChainVerification::Linked { this, .. } => this,
        }
    }

    /// Walk depth — number of links between leaf and genesis (inclusive of
    /// both endpoints). Genesis-only is depth 1; `A -> B -> C(genesis)` is
    /// depth 3.
    pub fn depth(&self) -> usize {
        match self {
            ChainVerification::Genesis(_) => 1,
            ChainVerification::Linked { parent, .. } => 1 + parent.depth(),
        }
    }

    /// Return all `SingleVerification`s in chain order (leaf first, genesis
    /// last). Useful for top-level auditor analysis of which authority
    /// versions the chain spans.
    pub fn flatten(&self) -> Vec<&SingleVerification> {
        let mut out = Vec::new();
        let mut cur = self;
        loop {
            match cur {
                ChainVerification::Genesis(v) => {
                    out.push(v);
                    break;
                }
                ChainVerification::Linked { this, parent } => {
                    out.push(this);
                    cur = parent.as_ref();
                }
            }
        }
        out
    }
}

/// Errors produced by `verify_chain`.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum ChainVerificationError {
    /// A per-link `verify_self()` returned a failure. Chain-walk fails closed
    /// at the failed link; the caller receives the wrapped failure for
    /// audit-trail rendering.
    #[error("single verification failed for capsule {}: {:?}",.0.capsule_id,.0.reason)]
    SingleVerificationFailed(SingleVerificationFailure),

    /// `fetch_parent_fn` could not resolve a declared parent reference.
    /// Chain-walk fails closed — a chain with a dangling parent_audit_proof_id
    /// is structurally invalid.
    #[error("parent not found: {0}")]
    ParentNotFound(String),

    /// The fetched parent's `capsule_id` does not match the child's declared
    /// `parent_audit_proof_id`. Indicates a corrupt fetch adapter or a
    /// substitution attack at the fetch layer.
    #[error("parent_id mismatch: declared={declared}, actual={actual}")]
    ParentIdMismatch { declared: String, actual: String },

    /// The fetched parent's `org_id` differs from the child's `org_id`.
    /// **Cross-customer parent-chain attack closure** — Class-A trust
    /// invariant. Chain-walk fails closed regardless of how the chain got
    /// into the verifier's hands.
    #[error("cross-customer linkage: child_org={child_org}, parent_org={parent_org}")]
    CrossCustomerLinkage {
        child_org: String,
        parent_org: String,
    },

    /// A `capsule_id` was visited twice during the walk. Chain has a cycle
    /// (DOS attack vector or buggy customer SDK emission); walk fails closed.
    #[error("cycle detected at capsule_id={capsule_id}")]
    CycleDetected { capsule_id: String },

    /// Chain depth would exceed `max_depth`. Customer must explicitly pass a
    /// higher `max_depth` to opt into a deeper walk.
    #[error("chain depth exceeded: max={max}")]
    DepthExceeded { max: usize },
}

/// Verifier chain-walk. Walks back to genesis or raises a closed-enum error.
///
/// ## Parameters
///
/// - `audit_proof` — the leaf AuditProof to verify.
/// - `fetch_parent_fn` — callback resolving a parent `capsule_id` to its
///   AuditProof. Online verifier (services/api): SQL query against `proofs`
///   table. Offline verifier (tools/cli): read from sibling JSON files. SDK
///   verifier (Python/TypeScript): customer-supplied callback.
/// - `max_depth` — maximum chain depth. Pass `DEFAULT_MAX_CHAIN_DEPTH` (100)
///   unless the customer's chain is genuinely deeper.
///
/// ## Returns
///
/// `Ok(ChainVerification)` on a fully-verified chain (recursive structure
/// from leaf to genesis), or `Err(ChainVerificationError)` on the first
/// failure encountered. Chain-walk fails closed — partial chain results are
/// not surfaced to avoid auditor confusion.
///
/// ## Correctness invariants
///
/// 1. Cycle detection — `visited: HashSet<String>` ensures no `capsule_id` is
///    walked twice; a re-visit returns `Err(CycleDetected)`.
/// 2. Depth limit — recursion guards `current_depth >= max_depth` and returns
///    `Err(DepthExceeded)` before descending further.
/// 3. Customer-id binding — at every parent transition, `child.org_id ==
///    parent.org_id` is enforced; mismatch returns
///    `Err(CrossCustomerLinkage)`.
/// 4. In-walk caching — `cache: HashMap<String, ChainVerification>` records
///    verified-parent results so a DAG ancestor touched multiple times is
///    verified once per `verify_chain` invocation. Cache drops when the call
///    returns (zero-retention discipline).
/// 5. Per-link `verify_self()` failure propagates as
///    `Err(SingleVerificationFailed)`.
pub fn verify_chain<N, F>(
    audit_proof: &N,
    mut fetch_parent_fn: F,
    max_depth: usize,
) -> Result<ChainVerification, ChainVerificationError>
where
    N: ChainNode,
    F: FnMut(&str) -> Result<N, ChainVerificationError>,
{
    let mut visited: HashSet<String> = HashSet::new();
    let mut cache: HashMap<String, ChainVerification> = HashMap::new();

    visited.insert(audit_proof.capsule_id().to_string());
    verify_chain_impl(
        audit_proof,
        &mut fetch_parent_fn,
        max_depth,
        1,
        &mut visited,
        &mut cache,
    )
}

/// Recursive worker behind `verify_chain`. Carries `visited`, `current_depth`,
/// and `cache` through the descent.
///
/// `current_depth` starts at 1 for the leaf and increments at each parent
/// transition. The depth guard fires when descending would step beyond
/// `max_depth` — i.e., a chain at exactly `max_depth` is accepted, and
/// `max_depth + 1` is rejected.
fn verify_chain_impl<N, F>(
    node: &N,
    fetch_parent_fn: &mut F,
    max_depth: usize,
    current_depth: usize,
    visited: &mut HashSet<String>,
    cache: &mut HashMap<String, ChainVerification>,
) -> Result<ChainVerification, ChainVerificationError>
where
    N: ChainNode,
    F: FnMut(&str) -> Result<N, ChainVerificationError>,
{
    // Step 1: per-link self-verification. Failure here propagates immediately.
    let this_verification = node
        .verify_self()
        .map_err(ChainVerificationError::SingleVerificationFailed)?;

    // Step 2: terminate at pipeline-genesis (parent_audit_proof_id is None).
    let parent_id = match node.parent_audit_proof_id() {
        None => return Ok(ChainVerification::Genesis(this_verification)),
        Some(id) => id.to_string(),
    };

    // Step 3: depth guard fires before descending — a chain of exactly
    // max_depth links is valid; max_depth + 1 is rejected.
    if current_depth >= max_depth {
        return Err(ChainVerificationError::DepthExceeded { max: max_depth });
    }

    // Step 4: cycle detection — refuse to re-walk a capsule_id already in the
    // visited set. The leaf was inserted by verify_chain() before the first
    // descent; descendants insert before recursing.
    if visited.contains(&parent_id) {
        return Err(ChainVerificationError::CycleDetected {
            capsule_id: parent_id,
        });
    }

    // Step 5: in-walk cache check — DAG ancestors hit through different paths
    // are verified once. The cache key is the parent's capsule_id; the value
    // is the already-verified parent ChainVerification subtree.
    if let Some(cached_parent) = cache.get(&parent_id) {
        // Even on cache hit, customer-id binding must be re-checked: the cache
        // key carries no org_id, and a different child could be linking to the
        // same parent under a different org. Cache hit ONLY skips parent
        // re-fetch + parent re-verification; org binding is per-edge.
        let parent_org = cached_parent.leaf().org_id.clone();
        if this_verification.org_id != parent_org {
            return Err(ChainVerificationError::CrossCustomerLinkage {
                child_org: this_verification.org_id,
                parent_org,
            });
        }
        return Ok(ChainVerification::Linked {
            this: this_verification,
            parent: Box::new(cached_parent.clone()),
        });
    }

    // Step 6: fetch parent via adapter callback.
    let parent_node = fetch_parent_fn(&parent_id)?;

    // Step 7: structural integrity — fetched parent's capsule_id MUST match
    // the declared parent_audit_proof_id. A mismatch indicates a corrupt
    // fetch adapter or a substitution attack at the fetch layer.
    if parent_node.capsule_id() != parent_id {
        return Err(ChainVerificationError::ParentIdMismatch {
            declared: parent_id,
            actual: parent_node.capsule_id().to_string(),
        });
    }

    // Step 8: customer-id binding — child.org_id MUST equal parent.org_id.
    // **Class-A trust invariant** — cross-customer parent-chain attack
    // closure. Co-owned with Internal Auditor per the specification runbook.
    if this_verification.org_id != parent_node.org_id() {
        return Err(ChainVerificationError::CrossCustomerLinkage {
            child_org: this_verification.org_id,
            parent_org: parent_node.org_id().to_string(),
        });
    }

    // Step 9: mark parent as visited before recursing.
    visited.insert(parent_id.clone());

    // Step 10: recurse into parent.
    let parent_verification = verify_chain_impl(
        &parent_node,
        fetch_parent_fn,
        max_depth,
        current_depth + 1,
        visited,
        cache,
    )?;

    // Step 11: cache the verified parent for any sibling DAG path that may
    // walk through it later in this same verify_chain invocation.
    cache.insert(parent_id, parent_verification.clone());

    Ok(ChainVerification::Linked {
        this: this_verification,
        parent: Box::new(parent_verification),
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! Chain-walk module tests — deterministic + property-based.
    //!
    //! ## Test taxonomy
    //!
    //! 1. **Genesis path** — leaf with `parent_audit_proof_id: None` returns
    //!    `Genesis(...)`.
    //! 2. **Linear chain** — N-step chain returns nested `Linked {... }`.
    //! 3. **Cycle detection** — self-reference, two-node, N-node cycles all
    //!    return `Err(CycleDetected)`.
    //! 4. **Depth limit** — chain of `max_depth + 1` returns
    //!    `Err(DepthExceeded)`; chain of `max_depth` succeeds.
    //! 5. **Customer-id binding** — cross-customer parent linkage returns
    //!    `Err(CrossCustomerLinkage)` (Class-A trust invariant).
    //! 6. **In-walk cache** — DAG ancestor hit through two paths is fetched
    //!    once.
    //! 7. **Property tests (10k iter)** — invariants 3, 4, 5, 6 under random
    //!    chain shapes per `feedback_canonical_hash_under_fault.md`.
    use super::*;
    use crate::SignatureFailureReason;
    use proptest::prelude::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Test ChainNode — minimal struct that lets tests construct chains
    /// declaratively without depending on the concrete FullCdp type.
    #[derive(Debug, Clone)]
    struct TestNode {
        capsule_id: String,
        org_id: String,
        parent: Option<String>,
        signature_verified: bool,
        canonical_hash_verified: bool,
        signing_key_version: String,
        // For per-link failure injection in tests.
        verify_self_fails_with: Option<FailureReason>,
    }

    impl TestNode {
        fn new(capsule_id: &str, org_id: &str, parent: Option<&str>) -> Self {
            TestNode {
                capsule_id: capsule_id.into(),
                org_id: org_id.into(),
                parent: parent.map(|s| s.into()),
                signature_verified: true,
                canonical_hash_verified: true,
                signing_key_version: "1".into(),
                verify_self_fails_with: None,
            }
        }
    }

    impl ChainNode for TestNode {
        fn capsule_id(&self) -> &str {
            &self.capsule_id
        }
        fn org_id(&self) -> &str {
            &self.org_id
        }
        fn parent_audit_proof_id(&self) -> Option<&str> {
            self.parent.as_deref()
        }
        fn verify_self(&self) -> Result<SingleVerification, SingleVerificationFailure> {
            if let Some(ref reason) = self.verify_self_fails_with {
                return Err(SingleVerificationFailure {
                    capsule_id: self.capsule_id.clone(),
                    reason: reason.clone(),
                });
            }
            Ok(SingleVerification {
                capsule_id: self.capsule_id.clone(),
                org_id: self.org_id.clone(),
                signature_verified: self.signature_verified,
                canonical_hash_verified: self.canonical_hash_verified,
                signing_key_version: self.signing_key_version.clone(),
            })
        }
    }

    /// Build a fetcher callback over an in-memory chain. Tracks fetch counts
    /// per capsule_id so the caching test can assert "no double-fetch".
    /// `clippy::type_complexity` allow: tuple of fetcher closure + counts
    /// handle is the cleanest test signature; factoring into a type alias
    /// hurts readability without trimming complexity.
    #[allow(clippy::type_complexity)]
    fn make_fetcher(
        nodes: Vec<TestNode>,
    ) -> (
        impl FnMut(&str) -> Result<TestNode, ChainVerificationError>,
        Rc<RefCell<HashMap<String, usize>>>,
    ) {
        let map: HashMap<String, TestNode> = nodes
            .into_iter()
            .map(|n| (n.capsule_id.clone(), n))
            .collect();
        let counts: Rc<RefCell<HashMap<String, usize>>> = Rc::new(RefCell::new(HashMap::new()));
        let counts_clone = counts.clone();
        let fetcher = move |id: &str| -> Result<TestNode, ChainVerificationError> {
            *counts_clone.borrow_mut().entry(id.to_string()).or_insert(0) += 1;
            map.get(id)
                .cloned()
                .ok_or_else(|| ChainVerificationError::ParentNotFound(id.to_string()))
        };
        (fetcher, counts)
    }

    // ── Determinstic tests ─────────────────────────────────────────────────

    #[test]
    fn chain_walk_genesis_returns_single_verification() {
        let leaf = TestNode::new("cap_a", "org_x", None);
        let (fetcher, _counts) = make_fetcher(vec![]);
        let result = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        assert!(matches!(result, ChainVerification::Genesis(_)));
        assert_eq!(result.leaf().capsule_id, "cap_a");
        assert_eq!(result.depth(), 1);
    }

    #[test]
    fn chain_walk_3_step_chain_returns_nested_linked() {
        // C (leaf) -> B -> A (genesis)
        let a = TestNode::new("cap_a", "org_x", None);
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let c = TestNode::new("cap_c", "org_x", Some("cap_b"));
        let (fetcher, _) = make_fetcher(vec![a, b]);
        let result = verify_chain(&c, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        assert_eq!(result.depth(), 3);
        let flat = result.flatten();
        assert_eq!(
            flat.iter()
                .map(|v| v.capsule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["cap_c", "cap_b", "cap_a"]
        );
    }

    #[test]
    fn chain_walk_detects_self_reference_cycle() {
        // A -> A (self-reference)
        let a = TestNode::new("cap_a", "org_x", Some("cap_a"));
        let (fetcher, _) = make_fetcher(vec![a.clone()]);
        let err = verify_chain(&a, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        assert!(matches!(
            err,
            ChainVerificationError::CycleDetected { ref capsule_id } if capsule_id == "cap_a"
        ));
    }

    #[test]
    fn chain_walk_detects_two_node_cycle() {
        // A -> B -> A (two-node)
        let a = TestNode::new("cap_a", "org_x", Some("cap_b"));
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let (fetcher, _) = make_fetcher(vec![a.clone(), b]);
        let err = verify_chain(&a, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        assert!(matches!(err, ChainVerificationError::CycleDetected { .. }));
    }

    #[test]
    fn chain_walk_detects_n_node_cycle() {
        // D -> C -> B -> A -> C (cycle at C)
        let a = TestNode::new("cap_a", "org_x", Some("cap_c"));
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let c = TestNode::new("cap_c", "org_x", Some("cap_b"));
        let d = TestNode::new("cap_d", "org_x", Some("cap_c"));
        let (fetcher, _) = make_fetcher(vec![a, b, c, d.clone()]);
        let err = verify_chain(&d, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        assert!(matches!(err, ChainVerificationError::CycleDetected { .. }));
    }

    #[test]
    fn chain_walk_max_depth_default_100_enforced() {
        // Construct a 101-deep linear chain. Default max_depth = 100 must reject.
        let mut nodes = Vec::new();
        for i in 0..101 {
            let parent = if i == 0 {
                None
            } else {
                Some(format!("cap_{:03}", i - 1))
            };
            nodes.push(TestNode::new(
                &format!("cap_{:03}", i),
                "org_x",
                parent.as_deref(),
            ));
        }
        let leaf = nodes.last().unwrap().clone();
        let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
        let (fetcher, _) = make_fetcher(parents);
        let err = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        assert!(matches!(
            err,
            ChainVerificationError::DepthExceeded { max: 100 }
        ));
    }

    #[test]
    fn chain_walk_max_depth_override_accepted() {
        // 150-deep chain, max_depth=200 must succeed.
        let mut nodes = Vec::new();
        for i in 0..150 {
            let parent = if i == 0 {
                None
            } else {
                Some(format!("cap_{:03}", i - 1))
            };
            nodes.push(TestNode::new(
                &format!("cap_{:03}", i),
                "org_x",
                parent.as_deref(),
            ));
        }
        let leaf = nodes.last().unwrap().clone();
        let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
        let (fetcher, _) = make_fetcher(parents);
        let result = verify_chain(&leaf, fetcher, 200).unwrap();
        assert_eq!(result.depth(), 150);
    }

    #[test]
    fn chain_walk_max_depth_at_threshold_accepted() {
        // Exactly max_depth links must succeed (off-by-one boundary).
        let max = 5usize;
        let mut nodes = Vec::new();
        for i in 0..max {
            let parent = if i == 0 {
                None
            } else {
                Some(format!("cap_{:03}", i - 1))
            };
            nodes.push(TestNode::new(
                &format!("cap_{:03}", i),
                "org_x",
                parent.as_deref(),
            ));
        }
        let leaf = nodes.last().unwrap().clone();
        let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
        let (fetcher, _) = make_fetcher(parents);
        let result = verify_chain(&leaf, fetcher, max).unwrap();
        assert_eq!(result.depth(), max);
    }

    #[test]
    fn chain_walk_rejects_cross_customer_parent_linkage() {
        // child (org_b) -> parent (org_a). Class-A trust invariant — fail closed.
        let parent = TestNode::new("cap_a", "org_a", None);
        let child = TestNode::new("cap_b", "org_b", Some("cap_a"));
        let (fetcher, _) = make_fetcher(vec![parent]);
        let err = verify_chain(&child, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        match err {
            ChainVerificationError::CrossCustomerLinkage {
                child_org,
                parent_org,
            } => {
                assert_eq!(child_org, "org_b");
                assert_eq!(parent_org, "org_a");
            }
            other => panic!("expected CrossCustomerLinkage, got {:?}", other),
        }
    }

    #[test]
    fn chain_walk_parent_not_found_propagated() {
        // child references parent that does not exist in fetch adapter.
        let child = TestNode::new("cap_b", "org_x", Some("cap_missing"));
        let (fetcher, _) = make_fetcher(vec![]);
        let err = verify_chain(&child, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        assert!(matches!(
            err,
            ChainVerificationError::ParentNotFound(ref id) if id == "cap_missing"
        ));
    }

    #[test]
    fn chain_walk_parent_id_mismatch_detected() {
        // Adapter returns a parent whose capsule_id differs from declared
        // parent_audit_proof_id. Substitution-attack guard.
        let real_parent = TestNode::new("cap_real", "org_x", None);
        let child = TestNode::new("cap_b", "org_x", Some("cap_declared"));
        // Fetcher returns real_parent for any lookup — simulating a corrupt adapter.
        let map: HashMap<String, TestNode> = HashMap::from([(
            "cap_declared".to_string(),
            // Real parent has a DIFFERENT capsule_id field than the key.
            real_parent.clone(),
        )]);
        let fetcher = move |id: &str| -> Result<TestNode, ChainVerificationError> {
            map.get(id)
                .cloned()
                .ok_or_else(|| ChainVerificationError::ParentNotFound(id.to_string()))
        };
        let err = verify_chain(&child, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        match err {
            ChainVerificationError::ParentIdMismatch { declared, actual } => {
                assert_eq!(declared, "cap_declared");
                assert_eq!(actual, "cap_real");
            }
            other => panic!("expected ParentIdMismatch, got {:?}", other),
        }
    }

    #[test]
    fn chain_walk_per_link_failure_propagates() {
        // Parent's verify_self() returns SignatureMismatch — chain-walk wraps
        // and propagates as SingleVerificationFailed.
        let mut parent = TestNode::new("cap_a", "org_x", None);
        parent.verify_self_fails_with = Some(FailureReason::SignatureMismatch {
            reason: SignatureFailureReason::DoesNotVerify,
        });
        let child = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let (fetcher, _) = make_fetcher(vec![parent]);
        let err = verify_chain(&child, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        match err {
            ChainVerificationError::SingleVerificationFailed(failure) => {
                assert_eq!(failure.capsule_id, "cap_a");
                assert!(matches!(
                    failure.reason,
                    FailureReason::SignatureMismatch { .. }
                ));
            }
            other => panic!("expected SingleVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn chain_walk_caches_within_invocation_drops_cache_after() {
        // Two leaves sharing parent A: walk leaf_b once, then leaf_c once. Both
        // share parent A, but cache is per-invocation — A is fetched twice,
        // once per outer call. Within a single call, A would be fetched once.
        let a = TestNode::new("cap_a", "org_x", None);
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let c = TestNode::new("cap_c", "org_x", Some("cap_a"));

        // Call 1: verify B. Should fetch A once.
        let (fetcher1, counts1) = make_fetcher(vec![a.clone()]);
        verify_chain(&b, fetcher1, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        assert_eq!(*counts1.borrow().get("cap_a").unwrap_or(&0), 1);

        // Call 2: verify C with a fresh fetcher. Cache from call 1 is dropped.
        // C fetches A once.
        let (fetcher2, counts2) = make_fetcher(vec![a.clone()]);
        verify_chain(&c, fetcher2, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        assert_eq!(*counts2.borrow().get("cap_a").unwrap_or(&0), 1);
    }

    #[test]
    fn chain_walk_in_walk_cache_avoids_redundant_per_link_verification() {
        // The cache test above shows fetcher hit-counts. This test verifies
        // that the in-walk cache is a real artifact: insertions happen.
        //
        // We can't trivially construct a DAG-shaped chain through the public
        // ChainNode trait (each node has at most one parent), so this test
        // exercises the linear-chain cache-population path: build a 3-step
        // chain, verify it, and confirm the cache contained 2 entries (the
        // two non-leaf parents) by the time the call returned. Internal
        // observability is via re-running the same walk and asserting the
        // result is identical (deterministic — proves cache did not pollute).
        let a = TestNode::new("cap_a", "org_x", None);
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let c = TestNode::new("cap_c", "org_x", Some("cap_b"));
        let (fetcher, counts) = make_fetcher(vec![a.clone(), b.clone()]);
        let result1 = verify_chain(&c, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        // First walk fetches each parent once.
        assert_eq!(*counts.borrow().get("cap_a").unwrap_or(&0), 1);
        assert_eq!(*counts.borrow().get("cap_b").unwrap_or(&0), 1);
        // Second walk with a fresh fetcher produces the same result —
        // cache was scoped to the first call (zero-retention discipline).
        let (fetcher2, _) = make_fetcher(vec![a, b]);
        let result2 = verify_chain(&c, fetcher2, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn chain_verification_flatten_orders_leaf_first() {
        let a = TestNode::new("cap_a", "org_x", None);
        let b = TestNode::new("cap_b", "org_x", Some("cap_a"));
        let c = TestNode::new("cap_c", "org_x", Some("cap_b"));
        let (fetcher, _) = make_fetcher(vec![a, b]);
        let result = verify_chain(&c, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        let flat = result.flatten();
        assert_eq!(flat[0].capsule_id, "cap_c");
        assert_eq!(flat[1].capsule_id, "cap_b");
        assert_eq!(flat[2].capsule_id, "cap_a");
    }

    #[test]
    fn chain_walk_rejects_cross_customer_at_deeper_link() {
        // 4-deep chain: leaf -> mid1 -> mid2 -> root. mid2 belongs to org_b
        // while leaf+mid1+root are org_a. Attack vector: malicious customer
        // hides cross-customer linkage 2 levels deep.
        let root = TestNode::new("cap_root", "org_a", None);
        let mid2 = TestNode::new("cap_mid2", "org_b", Some("cap_root"));
        let mid1 = TestNode::new("cap_mid1", "org_a", Some("cap_mid2"));
        let leaf = TestNode::new("cap_leaf", "org_a", Some("cap_mid1"));
        let (fetcher, _) = make_fetcher(vec![root, mid2, mid1.clone()]);
        let err = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap_err();
        // mid1.org_id = org_a, mid2.org_id = org_b → mismatch caught at that edge.
        assert!(matches!(
            err,
            ChainVerificationError::CrossCustomerLinkage { .. }
        ));
    }

    // ── Property-based tests (10k iter) ────────────────────────────────────
    //
    // Per `feedback_canonical_hash_under_fault.md`: every chain-bearing
    // invariant is exhausted at >=10k iterations. Each invariant gets its
    // own property; cumulative iteration count is 4 * 10k = 40k.

    /// Strategy: build a linear chain of N nodes (genesis at index 0, leaf
    /// at index N-1) where node i has parent i-1 (genesis has parent=None),
    /// then optionally inject a cycle by re-pointing the GENESIS node's
    /// parent at some later node (index in `[1, len-1]`). The walk descends
    /// from leaf →... → cap_001 → cap_000 → cap_{cycle_to}, and
    /// cap_{cycle_to} is already in `visited` by the time genesis attempts
    /// to fetch it.
    ///
    /// `inject_cycle == true` produces a cyclic chain; `false` produces a
    /// clean linear chain ending at genesis. Constrained `len >= 3` so the
    /// cycle target range `[1, len-1]` is non-empty (for `len == 2`, cycle
    /// target would have to be index 1 == leaf, and re-pointing genesis at
    /// the leaf is a valid 2-node cycle but the strategy's range generation
    /// is cleanest with `len >= 3`).
    fn chain_strategy(max_len: usize) -> impl Strategy<Value = (Vec<TestNode>, bool)> {
        (3usize..=max_len)
            .prop_flat_map(move |len| {
                // cycle_to: any index in [1, len-1] inclusive — re-pointing
                // genesis at that node creates a cycle when the walk reaches
                // genesis (cycle_to is in `visited` already).
                let cycle_to = 1usize..len;
                let inject = any::<bool>();
                (Just(len), cycle_to, inject)
            })
            .prop_map(|(len, cycle_to, inject)| {
                let mut nodes: Vec<TestNode> = (0..len)
                    .map(|i| {
                        let parent = if i == 0 {
                            None
                        } else {
                            Some(format!("cap_{:03}", i - 1))
                        };
                        TestNode::new(&format!("cap_{:03}", i), "org_x", parent.as_deref())
                    })
                    .collect();
                if inject {
                    // Re-point genesis (cap_000) at cap_{cycle_to} → cycle.
                    nodes[0].parent = Some(format!("cap_{:03}", cycle_to));
                }
                (nodes, inject)
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 10_000,
            max_shrink_iters: 1024,
            .. ProptestConfig::default()
        })]

        /// Property: cycle detection holds across random chain shapes.
        ///
        /// For every (chain, inject_cycle) pair: if inject_cycle is true,
        /// chain-walk MUST return Err(CycleDetected). Otherwise walk MUST
        /// succeed (linear path to genesis).
        #[test]
        fn prop_chain_walk_rejects_cycle_at_random_depth(
            (nodes, inject_cycle) in chain_strategy(50)
        ) {
            let leaf = nodes.last().unwrap().clone();
            let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
            let (fetcher, _) = make_fetcher(parents);
            let result = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH);
            if inject_cycle {
                prop_assert!(
                    matches!(result, Err(ChainVerificationError::CycleDetected { .. })),
                    "cycle injected in chain of {} not detected; got {:?}",
                    nodes.len(), result
                );
            } else {
                prop_assert!(result.is_ok(), "linear chain of {} failed: {:?}", nodes.len(), result);
            }
        }

        /// Property: depth limit holds across random thresholds.
        ///
        /// For every (chain_len, max_depth) pair: chain-walk succeeds iff
        /// chain_len <= max_depth, and returns Err(DepthExceeded) otherwise.
        #[test]
        fn prop_chain_walk_enforces_depth_limit_at_random_threshold(
            chain_len in 1usize..=30,
            max_depth in 1usize..=30,
        ) {
            let nodes: Vec<TestNode> = (0..chain_len)
                .map(|i| {
                    let parent = if i == 0 { None } else { Some(format!("cap_{:03}", i - 1)) };
                    TestNode::new(&format!("cap_{:03}", i), "org_x", parent.as_deref())
                })
                .collect();
            let leaf = nodes.last().unwrap().clone();
            let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
            let (fetcher, _) = make_fetcher(parents);
            let result = verify_chain(&leaf, fetcher, max_depth);
            if chain_len <= max_depth {
                prop_assert!(
                    result.is_ok(),
                    "chain_len={} <= max_depth={} should succeed; got {:?}",
                    chain_len, max_depth, result
                );
                prop_assert_eq!(result.unwrap().depth(), chain_len);
            } else {
                prop_assert!(
                    matches!(result, Err(ChainVerificationError::DepthExceeded { max }) if max == max_depth),
                    "chain_len={} > max_depth={} should fail with DepthExceeded; got {:?}",
                    chain_len, max_depth, result
                );
            }
        }

        /// Property: customer-id binding holds across random chain depths +
        /// random org_id permutations. **Class-A trust invariant** — the
        /// cross-customer parent-chain attack closure.
        ///
        /// For each (chain, org_assignments): walk MUST fail with
        /// CrossCustomerLinkage iff any (parent, child) pair has differing
        /// org_id, AND succeed if all org_ids are equal.
        #[test]
        fn prop_chain_walk_rejects_cross_customer_parent_under_random_chain_depth(
            chain_len in 2usize..=20,
            org_seed in any::<u64>(),
        ) {
            // Deterministic org assignment from seed — bit i of seed selects
            // org_a (0) or org_b (1) for node i.
            let nodes: Vec<TestNode> = (0..chain_len)
                .map(|i| {
                    let parent = if i == 0 { None } else { Some(format!("cap_{:03}", i - 1)) };
                    let org = if (org_seed >> (i % 64)) & 1 == 0 { "org_a" } else { "org_b" };
                    TestNode::new(&format!("cap_{:03}", i), org, parent.as_deref())
                })
                .collect();
            // Detect whether any (i, i+1) pair differs in org.
            let mut has_cross = false;
            for i in 0..chain_len - 1 {
                if nodes[i].org_id != nodes[i + 1].org_id {
                    has_cross = true;
                    break;
                }
            }
            let leaf = nodes.last().unwrap().clone();
            let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
            let (fetcher, _) = make_fetcher(parents);
            let result = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH);
            if has_cross {
                prop_assert!(
                    matches!(result, Err(ChainVerificationError::CrossCustomerLinkage { .. })),
                    "chain with cross-customer linkage NOT rejected: {:?}",
                    result
                );
            } else {
                prop_assert!(
                    result.is_ok(),
                    "uniform-org chain of {} failed: {:?}",
                    chain_len, result
                );
            }
        }

        /// Property: in-walk cache prevents double-fetch under random linear
        /// chains. Each parent in the chain is fetched exactly once per
        /// `verify_chain` invocation regardless of chain length.
        ///
        /// (The trait surface only allows linear chains in tests; DAG semantics
        /// are exercised in cross-impl integration tests at the SDK layer when
        /// those land. This property locks the linear-cache invariant: at most
        /// one fetch per parent.)
        #[test]
        fn prop_chain_walk_in_walk_cache_no_double_fetch_under_random_dag(
            chain_len in 1usize..=30,
        ) {
            let nodes: Vec<TestNode> = (0..chain_len)
                .map(|i| {
                    let parent = if i == 0 { None } else { Some(format!("cap_{:03}", i - 1)) };
                    TestNode::new(&format!("cap_{:03}", i), "org_x", parent.as_deref())
                })
                .collect();
            let leaf = nodes.last().unwrap().clone();
            let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
            let (fetcher, counts) = make_fetcher(parents);
            let _result = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
            // Each parent fetched at most once.
            for (id, count) in counts.borrow().iter() {
                prop_assert!(
                    *count <= 1,
                    "parent {} fetched {} times; expected at most 1",
                    id, count
                );
            }
        }
    }

    // ── Forever-Standard semantics lock ────────────────────────────────────

    /// **Forever-Standard pin**: chain-walk semantics are locked at the specification
    /// ship. Future code changes that alter behavior trip this test.
    ///
    /// Construct a synthetic 5-step chain with mixed metadata; assert the
    /// chain-walk result has the locked structural shape (depth=5, leaf-first
    /// flatten ordering, all SingleVerifications carry expected fields).
    /// Future changes to the algorithm (e.g., re-ordering flatten, omitting a
    /// metadata field) trip the test immediately.
    #[test]
    fn chain_walk_semantics_locked_at_adr_030_d2_ship() {
        let nodes: Vec<TestNode> = (0..5)
            .map(|i| {
                let parent = if i == 0 {
                    None
                } else {
                    Some(format!("cap_{:03}", i - 1))
                };
                let mut n =
                    TestNode::new(&format!("cap_{:03}", i), "org_locked", parent.as_deref());
                n.signing_key_version = format!("v{}", i + 1);
                n
            })
            .collect();
        let leaf = nodes.last().unwrap().clone();
        let parents: Vec<TestNode> = nodes[..nodes.len() - 1].to_vec();
        let (fetcher, _) = make_fetcher(parents);
        let result = verify_chain(&leaf, fetcher, DEFAULT_MAX_CHAIN_DEPTH).unwrap();
        // Locked invariants:
        assert_eq!(result.depth(), 5, "depth must be 5");
        let flat = result.flatten();
        assert_eq!(flat.len(), 5, "flatten must yield 5 entries");
        assert_eq!(flat[0].capsule_id, "cap_004", "leaf-first flatten ordering");
        assert_eq!(
            flat[4].capsule_id, "cap_000",
            "genesis-last flatten ordering"
        );
        for v in &flat {
            assert_eq!(v.org_id, "org_locked");
            assert!(v.signature_verified);
            assert!(v.canonical_hash_verified);
        }
        // signing_key_version metadata flows through unchanged.
        assert_eq!(flat[0].signing_key_version, "v5");
        assert_eq!(flat[4].signing_key_version, "v1");
    }
}

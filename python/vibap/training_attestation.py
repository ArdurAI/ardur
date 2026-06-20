"""Training-time identity attestation.

Research direction 3 (see docs/research/NOVEL-RESEARCH-DIRECTIONS-
2026-04-19.md). Closes the earliest-in-chain gap: *who trained the
model that the agent claims to be running.*

## The threat closed

SPIFFE attests runtime workload identity. Biscuit attests mission.
Neither attests training provenance. A compromised training pipeline
(poisoned dataset at stage 1, adversarial LoRA at stage 2, swapped
config at stage 3) produces a model whose runtime SPIFFE ID is
correct, whose Biscuit is signed validly, and whose weights have been
silently poisoned upstream.

Ardur's governance catches the RUNTIME side effects — the model
eventually tries a forbidden tool and gets denied. But the
intervening dataflow goes through adversary-chosen weights. For
narrow missions + sophisticated poisoning, the attack can stay inside
the mission's allowed scope while still advancing the attacker's
goal.

## The mechanism — in-toto-style signing chain with Merkle selection

Model provenance is structured as an **AttestationBundle** containing an
ordered chain of **AttestationLink** entries, each signed with ES256.
Semantics are borrowed from in-toto (SLSA-compatible) but specialized
for the model-weights case:

  link_0: training provider      — signs the base-weights materials
                                   hash + dataset manifest hash.
  link_1: fine-tune provider     — signs the adapter/LoRA materials
                                   hash + the base-weights link hash
                                   (chain linkage).
  link_2: deployment provider    — signs the (runtime-config + system-
                                   prompt) materials hash + the
                                   fine-tune link hash.

Each link's ``materials`` field is a Merkle tree over the actual
weight shards, so selective verification is cheap: verifying the LoRA
adapter doesn't require hashing 100 GB of base weights. Verifying
only the system prompt requires one SHA-256 on the prompt string.

The full bundle is referenced from a Biscuit credential via a new
``training_attestation_ref`` fact that carries the bundle's root
hash. At session start, the proxy:

  1. Extracts the attestation_ref from the Biscuit claims.
  2. Fetches the AttestationBundle from a registry (operator-
     configured HTTP endpoint / S3 / etc.; out of scope for this
     module).
  3. Verifies the full chain via :func:`verify_bundle`.
  4. Optionally, for selective-mode deployments, verifies only a
     specified subset of materials via :func:`verify_selective`.

If verification fails, the session is refused BEFORE any tool call
fires.

## What this module provides

  - :class:`MerkleTree` for content-addressed material sets.
  - :class:`AttestationLink` — the signed link format.
  - :class:`AttestationBundle` — ordered chain of links.
  - :func:`sign_link`, :func:`verify_bundle`, :func:`verify_selective`.
  - :class:`InMemoryAttestationRegistry` — test / demo registry.

## What this module does NOT do

  - **Fetch attestation bundles from the real world.** The registry
    Protocol is defined but the production implementation (S3-backed,
    SPIFFE-federated, etc.) is follow-up work.
  - **Attest weights at rest.** That's a separate problem — this
    module attests the SIGNING RELATIONSHIP between producers and
    the materials hashes they assert. Actual weight-hashing of 100 GB
    model files is follow-up work, probably via SPDX or SLSA materials
    manifests.
  - **Invent new crypto.** ES256 per FIPS 186-4; SHA-256 per FIPS
    180-4. The design is novel in composition, not in primitive
    selection (see docs/research/ON-ORIGINAL-CRYPTO-*.md).

## Relationship to existing Ardur layers

Biscuit carries ``training_attestation_ref`` (a reference). The bundle
itself lives out-of-band because it's large (Merkle tree metadata can
be megabytes for frontier models). The Biscuit remains compact. This
matches the real-world pattern for SBOM references and SLSA
provenance attestations — references in the credential, bulky
artifact in a registry.

The proxy's existing SPIFFE + Biscuit verification runs first. Only
after both pass does the proxy consult the attestation bundle. So
this layer is additive: sessions without an attestation_ref behave
identically to today's Biscuit sessions; sessions WITH an
attestation_ref can opt into the stronger posture.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol, runtime_checkable

import jwt
from cryptography.hazmat.primitives.asymmetric import ec


ALG = "ES256"


# --------------------------------------------------------------------------
# Canonical JSON helper — same shape as tool_response_provenance
# --------------------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# MerkleTree
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class MerkleTree:
    """Content-addressed material set with a deterministic root hash.

    Leaves are (name, sha256_of_content) pairs. The tree is a simple
    balanced binary Merkle tree; name ordering is lexicographic so the
    same materials always produce the same root regardless of insertion
    order. For small material sets (<1024 entries) this is efficient
    enough; large-model deployments with millions of weight shards
    would need a tiered design which is out of scope here.
    """

    leaves: tuple[tuple[str, str], ...]  # sorted ((name, sha256_hex), ...)

    @classmethod
    def from_materials(
        cls, materials: Mapping[str, bytes | str]
    ) -> "MerkleTree":
        """Build a tree from a mapping of name → content (bytes or hex).

        Each value may be:
          - ``bytes`` — will be SHA-256 hashed to produce the leaf
          - a 64-char lowercase hex string — interpreted as a
            pre-computed SHA-256 hash (useful when you're attesting
            large files you've already hashed elsewhere)
        """
        leaves: list[tuple[str, str]] = []
        for name in sorted(materials):
            value = materials[name]
            if isinstance(value, str):
                if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                    leaf_hash = value
                else:
                    raise ValueError(
                        f"material {name!r} str value must be 64-char lowercase "
                        f"hex (precomputed sha256); got {value!r}"
                    )
            elif isinstance(value, (bytes, bytearray, memoryview)):
                leaf_hash = sha256_hex(bytes(value))
            else:
                raise TypeError(
                    f"material {name!r} must be bytes or hex sha256 string, "
                    f"got {type(value).__name__}"
                )
            leaves.append((name, leaf_hash))
        return cls(leaves=tuple(leaves))

    @property
    def root(self) -> str:
        """Root hash. Empty tree has a well-defined sentinel root so
        distinguishable from 'no tree at all'."""
        if not self.leaves:
            return sha256_hex(b"ardur-merkle-empty-root-v1")
        # Each leaf's contribution is sha256(canonical(name, leaf_hash))
        current: list[str] = [
            sha256_hex(canonical_json([name, leaf_hash]))
            for name, leaf_hash in self.leaves
        ]
        while len(current) > 1:
            nxt: list[str] = []
            for i in range(0, len(current), 2):
                a = current[i]
                b = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(sha256_hex((a + b).encode("ascii")))
            current = nxt
        return current[0]

    def verify_leaf(self, name: str, content: bytes | str) -> bool:
        """Check whether a given (name, content) matches the tree."""
        if isinstance(content, str):
            expected = content
        else:
            expected = sha256_hex(bytes(content))
        for leaf_name, leaf_hash in self.leaves:
            if leaf_name == name:
                return leaf_hash == expected
        return False

    def has(self, name: str) -> bool:
        return any(leaf_name == name for leaf_name, _ in self.leaves)


# --------------------------------------------------------------------------
# AttestationLink — one signed claim in the chain
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationLink:
    """A single in-toto-style signed link in the attestation chain.

    Fields:
      role             — "training_provider", "fine_tune_provider",
                         "deployment_provider" (or custom role strings)
      signer_spiffe_id — the SPIFFE ID of the entity that produced
                         this link
      materials_root   — Merkle root of the materials this entity
                         attests to producing
      predecessor_hash — sha256 of the previous link's canonical JSON;
                         empty string for the first link
      signed_at        — unix timestamp; used for freshness checks
      extra            — arbitrary extra claims (version strings,
                         build IDs, tool versions, etc.)
      signature        — ES256 JWS over canonical_json of the claims
      key_id           — kid for resolver lookup
    """

    role: str
    signer_spiffe_id: str
    materials_root: str
    predecessor_hash: str
    signed_at: int
    extra: dict[str, Any]
    signature: str
    key_id: str

    def canonical_claims(self) -> dict[str, Any]:
        """The set of claims the signature covers.

        Excludes ``signature`` and ``key_id`` themselves since those
        wrap the claims, not the other way around.
        """
        return {
            "role": self.role,
            "signer_spiffe_id": self.signer_spiffe_id,
            "materials_root": self.materials_root,
            "predecessor_hash": self.predecessor_hash,
            "signed_at": self.signed_at,
            "extra": self.extra,
        }

    def canonical_hash(self) -> str:
        return sha256_hex(canonical_json(self.canonical_claims()))


def sign_link(
    *,
    role: str,
    signer_spiffe_id: str,
    materials_root: str,
    predecessor_hash: str,
    private_key: ec.EllipticCurvePrivateKey,
    key_id: str,
    extra: dict[str, Any] | None = None,
    signed_at: int | None = None,
) -> AttestationLink:
    """Produce a signed AttestationLink.

    The signature is an ES256 JWS over the canonical_claims dict. The
    JWS is self-contained — no external kid lookup is needed to read
    the claims, only to verify the signature.
    """
    if not role.strip():
        raise ValueError("role must be non-empty")
    if not signer_spiffe_id.strip():
        raise ValueError("signer_spiffe_id must be non-empty")
    if not key_id.strip():
        raise ValueError("key_id must be non-empty")
    issued = int(time.time()) if signed_at is None else int(signed_at)
    claims = {
        "role": role,
        "signer_spiffe_id": signer_spiffe_id,
        "materials_root": materials_root,
        "predecessor_hash": predecessor_hash,
        "signed_at": issued,
        "extra": dict(extra or {}),
    }
    jws = jwt.encode(
        claims, private_key, algorithm=ALG, headers={"kid": key_id}
    )
    return AttestationLink(
        role=role,
        signer_spiffe_id=signer_spiffe_id,
        materials_root=materials_root,
        predecessor_hash=predecessor_hash,
        signed_at=issued,
        extra=dict(extra or {}),
        signature=jws,
        key_id=key_id,
    )


# --------------------------------------------------------------------------
# AttestationBundle — ordered chain
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationBundle:
    """Ordered chain of :class:`AttestationLink`.

    The chain invariant: ``links[i].predecessor_hash ==
    links[i-1].canonical_hash()`` for i > 0; ``links[0].
    predecessor_hash == ""``. Verification enforces both.
    """

    links: tuple[AttestationLink, ...]

    @property
    def bundle_root(self) -> str:
        """A stable identifier for the bundle — hash of the ordered
        canonical claims of every link. Used as the
        ``training_attestation_ref`` fact value in Biscuit credentials
        so tampering with the bundle (inserting / removing / reordering
        links) changes the reference value.
        """
        serialized = canonical_json(
            [link.canonical_claims() for link in self.links]
        )
        return sha256_hex(serialized)


# --------------------------------------------------------------------------
# Resolver Protocol + in-memory implementation
# --------------------------------------------------------------------------


@runtime_checkable
class SignerKeyResolver(Protocol):
    """Looks up a signer's public key by key_id.

    Production implementations would query a Sigstore-style key
    registry, a SPIFFE federation bundle, or an operator-curated
    key store.
    """

    def resolve(self, key_id: str) -> ec.EllipticCurvePublicKey | None:
        raise NotImplementedError


@dataclass
class InMemorySignerRegistry:
    """Test/demo implementation of SignerKeyResolver."""

    _keys: dict[str, ec.EllipticCurvePublicKey] = field(default_factory=dict)

    def register(self, key_id: str, public_key: ec.EllipticCurvePublicKey) -> None:
        if not key_id.strip():
            raise ValueError("key_id must be non-empty")
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise TypeError("public_key must be EllipticCurvePublicKey")
        self._keys[key_id] = public_key

    def resolve(self, key_id: str) -> ec.EllipticCurvePublicKey | None:
        return self._keys.get(key_id)


# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleVerdict:
    """Result of verifying an AttestationBundle.

    ``verdict``:
      - ``VALID``    — every link's signature verifies, chain linkage
                       intact, all signers resolvable
      - ``INVALID``  — specific breakage; reason names which link and
                       which check failed
    """

    verdict: str
    reason: str
    verified_roles: tuple[str, ...] = ()
    bundle_root: str = ""


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_bundle(
    bundle: AttestationBundle,
    *,
    resolver: SignerKeyResolver,
    expected_roles: Iterable[str] | None = None,
    max_age_s: int | None = None,
    now: int | None = None,
) -> BundleVerdict:
    """Verify every link in the bundle.

    Checks, in order, with first-failure short-circuit:

      1. Bundle is non-empty.
      2. ``links[0].predecessor_hash == ""`` (start-of-chain marker).
      3. For every link:
         a. resolver knows key_id
         b. signature verifies (ES256 over canonical claims)
         c. header kid matches the link's key_id
         d. predecessor_hash matches the prior link's canonical_hash
            (for i > 0)
      4. If ``expected_roles`` given: the ordered role sequence
         exactly matches (prevents link-deletion attacks that preserve
         individual signatures but skip a required provider).
      5. If ``max_age_s`` given: every link's signed_at is within
         ``max_age_s`` of ``now``.

    Never raises — all error paths return BundleVerdict(INVALID, ...).
    """
    if not bundle.links:
        return BundleVerdict(verdict="INVALID", reason="empty bundle")

    if bundle.links[0].predecessor_hash != "":
        return BundleVerdict(
            verdict="INVALID",
            reason=(
                "first link must have empty predecessor_hash; got "
                f"{bundle.links[0].predecessor_hash!r}"
            ),
        )

    current = int(time.time()) if now is None else int(now)
    verified: list[str] = []

    for i, link in enumerate(bundle.links):
        # Chain linkage
        if i > 0:
            expected_predecessor = bundle.links[i - 1].canonical_hash()
            if link.predecessor_hash != expected_predecessor:
                return BundleVerdict(
                    verdict="INVALID",
                    reason=(
                        f"link {i} predecessor_hash "
                        f"({link.predecessor_hash[:12]}...) "
                        f"does not match previous link's canonical_hash "
                        f"({expected_predecessor[:12]}...)"
                    ),
                    verified_roles=tuple(verified),
                )

        # Key resolution
        public_key = resolver.resolve(link.key_id)
        if public_key is None:
            return BundleVerdict(
                verdict="INVALID",
                reason=f"link {i}: unknown key_id {link.key_id!r}",
                verified_roles=tuple(verified),
            )

        # Signature verification
        try:
            claims = jwt.decode(
                link.signature,
                public_key,
                algorithms=[ALG],
                options={
                    "require": ["role", "signer_spiffe_id", "materials_root",
                                "predecessor_hash", "signed_at"],
                    "verify_iat": False,  # signed_at is our iat; we check below
                },
            )
        except jwt.InvalidTokenError as exc:
            return BundleVerdict(
                verdict="INVALID",
                reason=(
                    f"link {i}: signature failed "
                    f"({type(exc).__name__}: {exc})"
                ),
                verified_roles=tuple(verified),
            )

        # Defense-in-depth: verify claims in signature match the link's
        # unsigned fields. If anyone constructed a link with
        # hand-written fields that disagree with the JWS payload, this
        # check catches it.
        if (claims["role"] != link.role
                or claims["signer_spiffe_id"] != link.signer_spiffe_id
                or claims["materials_root"] != link.materials_root
                or claims["predecessor_hash"] != link.predecessor_hash):
            return BundleVerdict(
                verdict="INVALID",
                reason=(
                    f"link {i}: signed claims disagree with link fields"
                ),
                verified_roles=tuple(verified),
            )

        # Header kid
        try:
            header = jwt.get_unverified_header(link.signature)
        except jwt.InvalidTokenError as exc:
            return BundleVerdict(
                verdict="INVALID",
                reason=f"link {i}: header parse failed ({exc})",
                verified_roles=tuple(verified),
            )
        if header.get("kid") != link.key_id:
            return BundleVerdict(
                verdict="INVALID",
                reason=(
                    f"link {i}: kid mismatch "
                    f"(header={header.get('kid')!r} "
                    f"link.key_id={link.key_id!r})"
                ),
                verified_roles=tuple(verified),
            )

        # Age. Round-5 hardening (FIX-R5-H6, 2026-04-28): the future-iat
        # bound runs UNCONDITIONALLY now, regardless of ``max_age_s``.
        # Round-4 audit flagged that the previous `if max_age_s is not
        # None:` gate meant a caller passing the default `max_age_s=None`
        # got NO future-iat check — accepting `signed_at=year_3000`
        # links indefinitely. The past-bound (`max_age_s`) remains
        # opt-in because legitimate archival re-verification needs it
        # disabled; the future-bound is always-on.
        signed_at = int(claims["signed_at"])
        future_age_s = signed_at - current
        if future_age_s > 60:
            return BundleVerdict(
                verdict="INVALID",
                reason=f"link {i}: signed_at is {future_age_s}s in the future",
                verified_roles=tuple(verified),
            )
        if max_age_s is not None:
            age = current - signed_at
            if age > max_age_s:
                return BundleVerdict(
                    verdict="INVALID",
                    reason=f"link {i}: stale ({age}s > {max_age_s}s)",
                    verified_roles=tuple(verified),
                )

        verified.append(link.role)

    # Optional role-sequence enforcement. Crucially this runs AFTER
    # every link is individually valid, so "valid signatures but the
    # order is wrong" still surfaces as INVALID rather than being
    # conflated with a missing link.
    if expected_roles is not None:
        expected_tuple = tuple(expected_roles)
        if tuple(verified) != expected_tuple:
            return BundleVerdict(
                verdict="INVALID",
                reason=(
                    f"role sequence mismatch: "
                    f"got {tuple(verified)}, expected {expected_tuple}"
                ),
                verified_roles=tuple(verified),
            )

    return BundleVerdict(
        verdict="VALID",
        reason="all links verified, chain intact",
        verified_roles=tuple(verified),
        bundle_root=bundle.bundle_root,
    )


def verify_selective(
    bundle: AttestationBundle,
    *,
    resolver: SignerKeyResolver,
    role: str,
    material_name: str,
    material_content: bytes | str,
    tree: MerkleTree,
) -> BundleVerdict:
    """Selective verification: check that a specific role's link attests
    to a specific material being in that role's Merkle tree.

    Use case: you want to verify that the deployment provider attests
    the system prompt without re-hashing a 100 GB base-weights set.
    Call with role='deployment_provider', material_name='system_prompt',
    material_content=<the prompt bytes>, tree=<the deployment_provider's
    Merkle tree>.

    The function:
      1. Runs full bundle verification first (no point trusting a
         selective check if the whole chain doesn't verify).
      2. Finds the link whose role == role.
      3. Verifies tree.root matches that link's materials_root.
      4. Verifies the named material is a member of the tree and its
         content hashes match.
    """
    full = verify_bundle(bundle, resolver=resolver)
    if full.verdict != "VALID":
        return full

    target_link: AttestationLink | None = None
    for link in bundle.links:
        if link.role == role:
            target_link = link
            break
    if target_link is None:
        return BundleVerdict(
            verdict="INVALID",
            reason=f"no link with role {role!r} in bundle",
            verified_roles=full.verified_roles,
            bundle_root=full.bundle_root,
        )

    if tree.root != target_link.materials_root:
        return BundleVerdict(
            verdict="INVALID",
            reason=(
                f"materials tree root ({tree.root[:12]}...) does not "
                f"match link's materials_root "
                f"({target_link.materials_root[:12]}...)"
            ),
            verified_roles=full.verified_roles,
            bundle_root=full.bundle_root,
        )

    if not tree.verify_leaf(material_name, material_content):
        return BundleVerdict(
            verdict="INVALID",
            reason=(
                f"material {material_name!r} not in tree or content "
                f"hash mismatch"
            ),
            verified_roles=full.verified_roles,
            bundle_root=full.bundle_root,
        )

    return BundleVerdict(
        verdict="VALID",
        reason=(
            f"role={role!r} attests material={material_name!r} "
            f"(bundle_root={full.bundle_root[:12]}...)"
        ),
        verified_roles=full.verified_roles,
        bundle_root=full.bundle_root,
    )

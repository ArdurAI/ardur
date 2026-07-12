"""Focused tests for the delegation flow. There's overlap with test_passport's
delegation suite; these are the 'agreed by all 3 reviewers' cases kept
explicit so a future refactor can't silently remove them."""

from __future__ import annotations

import hashlib

import jwt
import pytest

from vibap.passport import (
    MissionPassport,
    derive_child_passport,
    generate_keypair,
    issue_passport,
    verify_passport,
)


@pytest.fixture
def parent_token(private_key):
    mission = MissionPassport(
        agent_id="parent",
        mission="coordinate research",
        allowed_tools=["read", "write", "analyze", "search"],
        forbidden_tools=["delete"],
        resource_scope=["/data/*"],
        max_tool_calls=50,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=2,
    )
    return issue_passport(mission, private_key, ttl_s=600)


class TestScopeNarrowing:
    def test_child_scope_is_subset_of_parent(
        self, parent_token, private_key, public_key
    ):
        child = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read", "analyze"],
            child_mission="gather",
            child_ttl_s=300,
        )
        claims = verify_passport(child, public_key, parent_token=parent_token)
        parent_claims = verify_passport(parent_token, public_key)
        assert set(claims["allowed_tools"]).issubset(set(parent_claims["allowed_tools"]))

    def test_child_scope_cannot_equal_but_exceed_parent(
        self, parent_token, private_key, public_key
    ):
        """Keep equal sets, add a new tool — must fail."""
        with pytest.raises(PermissionError, match="scope escalation"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="child",
                child_allowed_tools=["read", "write", "analyze", "search", "rm_rf"],
                child_mission="evil",
                child_ttl_s=60,
            )


class TestMultiLevel:
    def test_grandchild_scope_subset_of_parent(
        self, parent_token, private_key, public_key
    ):
        child = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read", "analyze"],
            child_mission="child",
            child_ttl_s=300,
        )
        grand = derive_child_passport(
            parent_token=child,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="grand",
            child_allowed_tools=["read"],
            child_mission="grand",
            child_ttl_s=60,
        )
        grand_claims = verify_passport(grand, public_key, parent_token=child)
        assert grand_claims["allowed_tools"] == ["read"]
        assert grand_claims["max_delegation_depth"] == 0

    def test_chain_splice_detected_via_token_hash(
        self, parent_token, private_key, public_key
    ):
        """K1 regression: verify chain[0].token_hash prevents splice attacks.

        Create two independent delegation chains A→B and A'→C. Then verify
        that C presented with B as parent is rejected because chain[0].token_hash
        (embedded during A'→C derivation) won't match B's token hash.
        """
        # Chain 1: parent → child_B
        child_b = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child-b",
            child_allowed_tools=["read"],
            child_mission="legit-b",
        )

        # Chain 2: parent → child_a_prime → grandchild_c
        child_a_prime = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child-a-prime",
            child_allowed_tools=["read", "write"],
            child_mission="legit-a-prime",
        )
        grand_c = derive_child_passport(
            parent_token=child_a_prime,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="grand-c",
            child_allowed_tools=["read"],
            child_mission="grand-c",
        )

        # Splice: verify grand_c with child_b as parent → should fail.
        # The parent_jti check catches this first (child_b has a different jti
        # than child_a_prime). The chain[0].token_hash check is defense-in-depth
        # for cases where jti values could collide in multi-key deployments.
        with pytest.raises(PermissionError, match="parent_jti does not match|chain splice"):
            verify_passport(grand_c, public_key, parent_token=child_b)

        # Legitimate: verify grand_c with correct parent → should pass
        claims = verify_passport(grand_c, public_key, parent_token=child_a_prime)
        assert claims["sub"] == "grand-c"

    def test_grandchild_cannot_re_escalate(
        self, parent_token, private_key, public_key
    ):
        child = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],        # child is already narrowed
            child_mission="child",
            child_ttl_s=300,
        )
        # Even though parent had "write", child lost it — grandchild must not
        # regain it.
        with pytest.raises(PermissionError, match="scope escalation"):
            derive_child_passport(
                parent_token=child,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="grand",
                child_allowed_tools=["read", "write"],
                child_mission="sneaky",
                child_ttl_s=60,
            )


class TestTTLClamping:
    def test_child_ttl_never_exceeds_parent(self, private_key, public_key):
        mission = MissionPassport(
            agent_id="short-parent",
            mission="short",
            allowed_tools=["read"],
            delegation_allowed=True,
            max_delegation_depth=1,
            max_duration_s=10,
        )
        parent = issue_passport(mission, private_key, ttl_s=10)
        parent_exp = verify_passport(parent, public_key)["exp"]

        child = derive_child_passport(
            parent_token=parent,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="c",
            child_ttl_s=10_000,  # intentionally absurd
        )
        child_exp = verify_passport(child, public_key, parent_token=parent)["exp"]
        assert child_exp <= parent_exp


class TestBudgetNarrowing:
    """Regression tests for external-review-X audit C-2 / feature-dev BUG-02:
    child must NOT inherit the parent's full budget."""

    def test_child_budget_capped_at_parent_remaining(self, private_key, public_key):
        """If parent has used 45/50, child can't get more than 5 calls even if requested."""
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=50,
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_max_tool_calls=100,  # request more than parent has
            parent_calls_remaining=5,  # parent has only 5 left
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["max_tool_calls"] == 5, (
            "child budget must be min(requested, remaining, ceiling) = 5"
        )

    def test_child_budget_explicit_request_is_respected(self, private_key, public_key):
        """Caller can ask for a smaller child budget than parent has."""
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=100,
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_max_tool_calls=10,
            parent_calls_remaining=100,
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["max_tool_calls"] == 10

    def test_exhausted_parent_budget_blocks_delegation(self, private_key, public_key):
        """Parent with 0 remaining cannot spawn a child."""
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                max_tool_calls=10,
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        with pytest.raises(PermissionError, match="budget exhausted"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="c",
                child_allowed_tools=["read"],
                child_mission="sub",
                parent_calls_remaining=0,
            )


class TestResourceScopeNarrowing:
    """Regression tests for external-review-G audit 2.2: child resource_scope was copied
    verbatim (never intersected). Now child can request narrower scope."""

    def test_child_scope_subset_accepted(self, private_key, public_key):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=["/data/*", "/reports/*", "/logs/*"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_resource_scope=["/data/*"],  # subset
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["resource_scope"] == ["/data/*"]

    def test_child_scope_escalation_rejected(self, private_key, public_key):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=["/data/*"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        with pytest.raises(PermissionError, match="scope escalation \\(resources\\)"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="c",
                child_allowed_tools=["read"],
                child_mission="sub",
                child_resource_scope=["/data/*", "/hr/*"],  # adds /hr/*
            )

    def test_child_scope_default_inherits_parent(self, private_key, public_key):
        """If caller doesn't specify child scope, parent's is inherited verbatim."""
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=["/data/*", "/logs/*"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["resource_scope"] == ["/data/*", "/logs/*"]

    def test_unrestricted_parent_can_delegate_narrowed_child_scope(self, private_key, public_key):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=["**"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_resource_scope=["/tmp/*"],
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["resource_scope"] == ["/tmp/*"]

    def test_absent_parent_scope_cannot_delegate_resource_authority(
        self, private_key, public_key
    ):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=[],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        with pytest.raises(PermissionError, match="scope escalation \\(resources\\)"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="c",
                child_allowed_tools=["read"],
                child_mission="sub",
                child_resource_scope=["/tmp/*"],
            )

    def test_restricted_parent_can_delegate_empty_child_scope(self, private_key, public_key):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                resource_scope=["/data/*"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_resource_scope=[],
        )
        claims = verify_passport(child_token, public_key, parent_token=parent_token)
        assert claims["resource_scope"] == []


class TestEmptyChildTools:
    """Regression: empty child_allowed_tools produced a do-nothing credential."""

    def test_empty_child_tools_rejected(self, private_key, public_key):
        parent_token = issue_passport(
            MissionPassport(
                agent_id="p",
                mission="coord",
                allowed_tools=["read"],
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=600,
        )
        with pytest.raises(PermissionError, match="non-empty"):
            derive_child_passport(
                parent_token=parent_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="c",
                child_allowed_tools=[],  # empty
                child_mission="do nothing",
            )


class TestDelegationChainAdversarial:
    """Adversarial chain cases modeled after capability-token runtimes, but
    expressed in VIBAP's signed passport vocabulary.

    The important boundary: a delegated passport must be self-describing
    enough to reject malformed lineage before the verifier has a raw parent
    token available. Supplying parent_token adds hash verification, but it
    must not be the only path that validates delegation_chain shape.
    """

    def _parent(self, private_key) -> str:
        return issue_passport(
            MissionPassport(
                agent_id="root",
                mission="coordinate chain validation",
                allowed_tools=["read", "write"],
                max_tool_calls=20,
                delegation_allowed=True,
                max_delegation_depth=2,
            ),
            private_key,
            ttl_s=300,
        )

    def _signed_child(
        self,
        *,
        private_key,
        parent_token: str,
        public_key,
        extra_claims: dict[str, object] | None = None,
    ) -> str:
        parent_claims = verify_passport(parent_token, public_key)
        claims = {
            "parent_token_hash": hashlib.sha256(
                parent_token.encode("utf-8")
            ).hexdigest(),
        }
        if extra_claims:
            claims.update(extra_claims)
        return issue_passport(
            MissionPassport(
                agent_id="child",
                mission="forged child",
                allowed_tools=["read"],
                max_tool_calls=5,
                delegation_allowed=False,
                max_delegation_depth=0,
                parent_jti=parent_claims["jti"],
            ),
            private_key,
            ttl_s=60,
            extra_claims=claims,
        )

    def test_orphan_child_without_chain_rejected_even_without_parent_token(
        self, private_key, public_key
    ):
        parent_token = self._parent(private_key)
        orphan = self._signed_child(
            private_key=private_key,
            parent_token=parent_token,
            public_key=public_key,
        )

        with pytest.raises(PermissionError, match="missing delegation_chain"):
            verify_passport(orphan, public_key)

    def test_unordered_chain_rejected_even_without_parent_token(
        self, private_key, public_key
    ):
        parent_token = self._parent(private_key)
        parent_claims = verify_passport(parent_token, public_key)
        forged = self._signed_child(
            private_key=private_key,
            parent_token=parent_token,
            public_key=public_key,
            extra_claims={
                "delegation_chain": [
                    {"jti": "not-the-immediate-parent"},
                    {"jti": parent_claims["jti"]},
                ],
            },
        )

        with pytest.raises(PermissionError, match="inconsistent delegation_chain"):
            verify_passport(forged, public_key)

    def test_cycle_rejected_even_without_parent_token(
        self, private_key, public_key
    ):
        parent_token = self._parent(private_key)
        parent_claims = verify_passport(parent_token, public_key)
        forged = self._signed_child(
            private_key=private_key,
            parent_token=parent_token,
            public_key=public_key,
            extra_claims={
                "jti": "forged-child-jti",
                "delegation_chain": [
                    {"jti": parent_claims["jti"], "parent_jti": "forged-child-jti"},
                    {"jti": "forged-child-jti"},
                ],
            },
        )

        with pytest.raises(PermissionError, match="lineage cycle"):
            verify_passport(forged, public_key)

    def test_child_signed_by_wrong_key_is_rejected_by_issuer_verifier(
        self, tmp_path, private_key, public_key
    ):
        parent_token = self._parent(private_key)
        attacker_private_key, _ = generate_keypair(keys_dir=tmp_path / "attacker")

        wrong_signer_child = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=attacker_private_key,
            child_agent_id="wrong-signer",
            child_allowed_tools=["read"],
            child_mission="signed by an untrusted issuer",
        )

        with pytest.raises(jwt.InvalidSignatureError):
            verify_passport(wrong_signer_child, public_key)


class TestEscrowRights:
    """Sprint #17 (April 15 2026): escrow-rights primitive for sibling-budget
    amplification fix. STAC delegation probe (April 14 2026) showed VIBAP
    catching 0/10 sibling-budget-amplification attacks at the cryptographic
    boundary because callers could omit lineage-state signals. The
    ``parent_reserved_for_descendants`` parameter and ``reserved_budget_share``
    claim close that gap. See unified-steps-final.md §3.6."""

    def _root(self, private_key, ceiling: int = 30) -> str:
        mission = MissionPassport(
            agent_id="root",
            mission="coordinate fan-out",
            allowed_tools=["read", "write"],
            max_tool_calls=ceiling,
            max_duration_s=600,
            delegation_allowed=True,
            max_delegation_depth=3,
        )
        return issue_passport(mission, private_key, ttl_s=600)

    def test_first_child_includes_reserved_budget_share_claim(
        self, private_key, public_key
    ):
        root_token = self._root(private_key, ceiling=30)
        child_token = derive_child_passport(
            parent_token=root_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c1",
            child_allowed_tools=["read"],
            child_mission="sub",
            child_max_tool_calls=10,
        )
        claims = verify_passport(child_token, public_key, parent_token=root_token)
        # Audit claim: every child carries its reserved share of the
        # ancestor budget. A verifier walking a chain sums these to check
        # conservation against any ancestor's max_tool_calls.
        assert claims["reserved_budget_share"] == 10

    def test_third_sibling_rejected_when_reservations_exhaust_ceiling(
        self, private_key, public_key
    ):
        """Root ceiling=30. Two prior siblings reserved 10 each. Third
        sibling requesting 15 with parent_reserved_for_descendants=20 must
        be clamped to 10 (= 30-20), not 15. A naive caller that didn't
        report reservations would mint a 15-call third child, yielding tree
        budget 35 > root 30. The escrow check refuses that."""
        root_token = self._root(private_key, ceiling=30)
        third = derive_child_passport(
            parent_token=root_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="c3",
            child_allowed_tools=["read"],
            child_mission="third sibling",
            child_max_tool_calls=15,                     # asks for 15
            parent_reserved_for_descendants=20,           # 2 prior sibs * 10
        )
        claims = verify_passport(third, public_key, parent_token=root_token)
        # Clamped to escrow_remaining = ceiling(30) - reserved(20) = 10
        assert claims["max_tool_calls"] == 10
        assert claims["reserved_budget_share"] == 10

    def test_ceiling_exhausted_rejects_delegation(
        self, private_key, public_key
    ):
        """If parent_reserved_for_descendants == ceiling, no further
        delegation may occur even if parent_calls_remaining is silent
        about the exhaustion."""
        root_token = self._root(private_key, ceiling=30)
        with pytest.raises(PermissionError, match="descendant-reservation pool exhausted"):
            derive_child_passport(
                parent_token=root_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="cN",
                child_allowed_tools=["read"],
                child_mission="last attempt",
                child_max_tool_calls=5,
                parent_reserved_for_descendants=30,  # already at ceiling
            )

    def test_over_allocated_reservation_rejected(
        self, private_key, public_key
    ):
        """Defensive: a caller that reports more reserved than the ceiling
        is mathematically impossible — refuse rather than accept and
        compute a negative escrow_remaining."""
        root_token = self._root(private_key, ceiling=30)
        with pytest.raises(PermissionError, match="exceeds parent ceiling"):
            derive_child_passport(
                parent_token=root_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="bad",
                child_allowed_tools=["read"],
                child_mission="bad reservation report",
                child_max_tool_calls=5,
                parent_reserved_for_descendants=31,  # > ceiling
            )

    def test_negative_reservation_rejected(
        self, private_key, public_key
    ):
        root_token = self._root(private_key, ceiling=30)
        with pytest.raises(PermissionError, match="must be non-negative"):
            derive_child_passport(
                parent_token=root_token,
                public_key=public_key,
                private_key=private_key,
                child_agent_id="bad",
                child_allowed_tools=["read"],
                child_mission="bad",
                child_max_tool_calls=5,
                parent_reserved_for_descendants=-1,
            )

    def test_default_zero_reservation_preserves_back_compat(
        self, private_key, public_key
    ):
        """Existing call sites that don't pass parent_reserved_for_descendants
        get the default 0 — same behavior as before this sprint. The
        proxy still adds defense-in-depth via lineage state when it sits
        in front of derivations."""
        root_token = self._root(private_key, ceiling=30)
        child_token = derive_child_passport(
            parent_token=root_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="back-compat",
            child_allowed_tools=["read"],
            child_mission="legacy caller",
            child_max_tool_calls=10,
            # parent_reserved_for_descendants omitted — defaults to 0
        )
        claims = verify_passport(
            child_token, public_key, parent_token=root_token
        )
        assert claims["max_tool_calls"] == 10
        assert claims["reserved_budget_share"] == 10


class TestColdLineageVerification:
    """Regression suite for the signed-chain verification boundary.

    Delegated verification must be anchored by either the raw parent token
    or an authoritative jti->token_hash registry. A self-consistent signed
    chain alone is not enough because it can reference a fabricated parent.
    """

    def _root(self, private_key) -> str:
        return issue_passport(
            MissionPassport(
                agent_id="root",
                mission="coordinate",
                allowed_tools=["read", "write"],
                max_tool_calls=20,
                max_duration_s=300,
                delegation_allowed=True,
                max_delegation_depth=3,
            ),
            private_key,
            ttl_s=300,
        )

    def test_child_with_fabricated_parent_jti_rejected_when_parent_token_supplied(
        self, private_key, public_key
    ):
        """Parent-token anchoring detects a fabricated immediate parent."""
        root_token = self._root(private_key)
        root_claims = verify_passport(root_token, public_key)
        fake_parent_jti = "fake-00000000-0000-0000-0000-000000000000"
        fake_parent_hash = "0" * 64
        forged = issue_passport(
            MissionPassport(
                agent_id="child",
                mission="no real parent",
                allowed_tools=["read"],
                max_tool_calls=5,
                max_duration_s=60,
                parent_jti=fake_parent_jti,
            ),
            private_key,
            ttl_s=60,
            extra_claims={
                "parent_token_hash": fake_parent_hash,
                "delegation_chain": [
                    {"jti": fake_parent_jti, "token_hash": fake_parent_hash},
                ],
            },
        )
        with pytest.raises(PermissionError, match="parent_jti does not match"):
            verify_passport(forged, public_key, parent_token=root_token)
        with pytest.raises(PermissionError, match="not trusted"):
            verify_passport(
                forged,
                public_key,
                trusted_parent_token_hashes={
                    root_claims["jti"]: hashlib.sha256(
                        root_token.encode("utf-8")
                    ).hexdigest()
                },
                trusted_parent_lineage={root_claims["jti"]: (None, None)},
            )

    def test_legit_child_rejected_without_parent_token_or_trusted_hashes(
        self, private_key, public_key
    ):
        parent_token = self._root(private_key)
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="subtask",
            child_ttl_s=120,
        )
        with pytest.raises(PermissionError, match="trusted_parent_token_hashes"):
            verify_passport(child_token, public_key)

    def test_legit_child_passes_with_trusted_parent_hashes(
        self, private_key, public_key
    ):
        parent_token = self._root(private_key)
        parent_claims = verify_passport(parent_token, public_key)
        parent_hash = hashlib.sha256(parent_token.encode("utf-8")).hexdigest()
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="subtask",
            child_ttl_s=120,
        )

        claims = verify_passport(
            child_token,
            public_key,
            trusted_parent_token_hashes={
                parent_claims["jti"]: parent_hash,
            },
            trusted_parent_lineage={parent_claims["jti"]: (None, None)},
        )
        assert claims["sub"] == "child"
        assert claims["parent_jti"]

    def test_cold_child_rejects_trusted_hash_without_trusted_lineage(
        self, private_key, public_key
    ):
        parent_token = self._root(private_key)
        parent_claims = verify_passport(parent_token, public_key)
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="subtask",
            child_ttl_s=120,
        )

        with pytest.raises(PermissionError, match="trusted_parent_lineage"):
            verify_passport(
                child_token,
                public_key,
                trusted_parent_token_hashes={
                    parent_claims["jti"]: hashlib.sha256(
                        parent_token.encode("utf-8")
                    ).hexdigest()
                },
            )

    def test_grandchild_cannot_rewrite_parent_ancestor_edge(
        self, private_key, public_key
    ):
        root_token = self._root(private_key)
        root_claims = verify_passport(root_token, public_key)
        root_hash = hashlib.sha256(root_token.encode("utf-8")).hexdigest()
        child_token = derive_child_passport(
            parent_token=root_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="subtask",
            child_ttl_s=120,
        )
        child_claims = verify_passport(
            child_token,
            public_key,
            parent_token=root_token,
        )
        child_hash = hashlib.sha256(child_token.encode("utf-8")).hexdigest()
        forged_grandchild = issue_passport(
            MissionPassport(
                agent_id="grandchild",
                mission="hide ancestor",
                allowed_tools=["read"],
                parent_jti=child_claims["jti"],
            ),
            private_key,
            ttl_s=60,
            extra_claims={
                "parent_token_hash": child_hash,
                "delegation_chain": [
                    {"jti": child_claims["jti"], "token_hash": child_hash},
                ],
            },
        )

        with pytest.raises(PermissionError, match="supplied parent lineage"):
            verify_passport(
                forged_grandchild,
                public_key,
                parent_token=child_token,
            )
        with pytest.raises(PermissionError, match="parent_jti is not trusted"):
            verify_passport(
                forged_grandchild,
                public_key,
                trusted_parent_token_hashes={
                    child_claims["jti"]: child_hash,
                    root_claims["jti"]: root_hash,
                },
                trusted_parent_lineage={
                    child_claims["jti"]: (root_claims["jti"], root_hash),
                    root_claims["jti"]: (None, None),
                },
            )

    def test_legit_child_passes_when_parent_token_supplied(
        self, private_key, public_key
    ):
        """Supplying parent_token adds immediate parent hash anchoring."""
        parent_token = self._root(private_key)
        child_token = derive_child_passport(
            parent_token=parent_token,
            public_key=public_key,
            private_key=private_key,
            child_agent_id="child",
            child_allowed_tools=["read"],
            child_mission="subtask",
            child_ttl_s=120,
        )
        claims = verify_passport(
            child_token, public_key, parent_token=parent_token
        )
        assert claims["sub"] == "child"
        assert claims["parent_jti"]  # chain intact

    def test_root_passport_still_verifies_without_parent_token(
        self, private_key, public_key
    ):
        """A root passport has no lineage and still verifies in 2-arg form."""
        root_token = issue_passport(
            MissionPassport(
                agent_id="root",
                mission="solo",
                allowed_tools=["read"],
                max_tool_calls=5,
                max_duration_s=60,
            ),
            private_key,
            ttl_s=60,
        )
        claims = verify_passport(root_token, public_key)
        assert claims["sub"] == "root"
        assert claims.get("parent_jti") is None

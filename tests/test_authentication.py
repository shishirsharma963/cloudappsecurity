"""Tests for cryptographic authentication invariants."""

import time

import pytest
import jwt
from cloud_security_case import auth, scenarios


def test_valid_token_verification():
    """Verify that a legitimately minted token passes verification."""
    token = scenarios.cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = scenarios.cognito.verify_token(token, expected_audience="fitness_api")
    assert claims["sub"] == "usr_alice"
    assert claims["email"] == "alice@gmail.com"
    assert claims["aud"] == "fitness_api"


def test_expired_token_raises_error():
    """Verify that expired tokens are cryptographically rejected."""
    token = scenarios.cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
        ttl_seconds=-5,  # 5 seconds in the past
    )
    with pytest.raises(auth.AuthenticationError) as exc_info:
        scenarios.cognito.verify_token(token, expected_audience="fitness_api")
    assert "expired" in str(exc_info.value)


def test_wrong_audience_raises_error():
    """Verify that a token with incorrect audience claims is rejected."""
    token = scenarios.cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="different_api",
    )
    with pytest.raises(auth.AuthenticationError) as exc_info:
        scenarios.cognito.verify_token(token, expected_audience="fitness_api")
    assert "wrong audience" in str(exc_info.value)


def test_forged_signature_raises_error():
    """Verify that a token signed by an unauthorized key pair is rejected."""
    evil_provider = auth.CognitoProvider()
    evil_token = evil_provider.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    with pytest.raises(auth.AuthenticationError) as exc_info:
        scenarios.cognito.verify_token(evil_token, expected_audience="fitness_api")
    assert "invalid token signature" in str(exc_info.value)


def test_revoked_jti_rejected_despite_valid_signature():
    """A cryptographically valid token dies at the deny-list check."""
    deny_list = auth.RevocationList()
    token = scenarios.cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="fitness_api",
    )
    claims = scenarios.cognito.verify_token(
        token, expected_audience="fitness_api", revocation_list=deny_list
    )

    deny_list.revoke_jti(claims["jti"], token_exp=claims["exp"])
    with pytest.raises(auth.TokenRevokedError):
        scenarios.cognito.verify_token(
            token, expected_audience="fitness_api", revocation_list=deny_list
        )


def test_subject_revocation_kills_all_prior_tokens():
    """GlobalSignOut semantics: every token issued before the cutoff is dead."""
    deny_list = auth.RevocationList()
    token_a = scenarios.cognito.mint_token(
        user_id="usr_alice", email="alice@gmail.com",
        client_id="client_mobile_app", audience="fitness_api",
    )
    token_b = scenarios.cognito.mint_token(
        user_id="usr_alice", email="alice@gmail.com",
        client_id="client_mobile_app", audience="fitness_api",
    )

    deny_list.revoke_subject("usr_alice")

    for token in (token_a, token_b):
        with pytest.raises(auth.TokenRevokedError):
            scenarios.cognito.verify_token(
                token, expected_audience="fitness_api", revocation_list=deny_list
            )


def test_post_reauth_token_survives_subject_revocation():
    """A token minted AFTER the sign-out cutoff must be honored (re-login works)."""
    deny_list = auth.RevocationList()
    # Sign-out happened in the past; the fresh token's iat is after the cutoff
    deny_list.revoke_subject("usr_alice", not_before=int(time.time()) - 10)

    fresh_token = scenarios.cognito.mint_token(
        user_id="usr_alice", email="alice@gmail.com",
        client_id="client_mobile_app", audience="fitness_api",
    )
    claims = scenarios.cognito.verify_token(
        fresh_token, expected_audience="fitness_api", revocation_list=deny_list
    )
    assert claims["sub"] == "usr_alice"


def test_deny_list_tombstones_self_expire():
    """Entries evict once the underlying token would have expired anyway."""
    deny_list = auth.RevocationList()
    past_exp = int(time.time()) - 5
    deny_list.revoke_jti("jti_already_expired", token_exp=past_exp)

    # An eviction pass drops the stale tombstone: bounded memory
    assert deny_list.is_revoked({"jti": "jti_already_expired", "sub": "x", "iat": 0}) is False
    assert deny_list._revoked_jti == {}

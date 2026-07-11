"""Tests for cryptographic authentication invariants."""

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

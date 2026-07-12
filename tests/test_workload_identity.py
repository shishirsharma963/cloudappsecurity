"""Tests for the workload identity token exchange (service-to-service auth)."""

import pytest
from cloud_security_case import auth


@pytest.fixture
def broker():
    b = auth.WorkloadIdentityBroker()
    b.register_workload(
        "wearable-import-worker",
        attestation_secret="platform-attest-import-worker",
        scopes=["runs:write", "queue:consume"],
    )
    return b


def test_registered_workload_exchange_and_verify(broker):
    """A registered workload with valid attestation gets a verifiable scoped token."""
    token = broker.exchange_token(
        "wearable-import-worker",
        "platform-attest-import-worker",
        audience="internal_runs_api",
        requested_scopes=["runs:write"],
    )
    claims = broker.verify_service_call(
        token, expected_audience="internal_runs_api", required_scope="runs:write"
    )
    assert claims["sub"] == "spiffe://fitnesslog.internal/workload/wearable-import-worker"
    assert claims["token_use"] == "workload"


def test_unregistered_workload_is_denied(broker):
    """A workload without a trust registration cannot obtain a token."""
    with pytest.raises(auth.WorkloadIdentityError, match="no trust registration"):
        broker.exchange_token(
            "rogue-cryptominer",
            "guessed-secret",
            audience="internal_runs_api",
            requested_scopes=["runs:write"],
        )


def test_failed_attestation_is_denied(broker):
    """A registered workload name with the wrong attestation secret is rejected."""
    with pytest.raises(auth.WorkloadIdentityError, match="attestation failed"):
        broker.exchange_token(
            "wearable-import-worker",
            "wrong-secret",
            audience="internal_runs_api",
            requested_scopes=["runs:write"],
        )


def test_scope_escalation_is_denied(broker):
    """Requesting scopes beyond the registration is refused at exchange time."""
    with pytest.raises(auth.WorkloadIdentityError, match="scope escalation denied"):
        broker.exchange_token(
            "wearable-import-worker",
            "platform-attest-import-worker",
            audience="internal_runs_api",
            requested_scopes=["runs:write", "users:delete"],
        )


def test_token_missing_required_scope_is_denied(broker):
    """A valid service token cannot call an endpoint outside its granted scopes."""
    token = broker.exchange_token(
        "wearable-import-worker",
        "platform-attest-import-worker",
        audience="internal_runs_api",
        requested_scopes=["queue:consume"],
    )
    with pytest.raises(auth.WorkloadIdentityError, match="insufficient scope"):
        broker.verify_service_call(
            token, expected_audience="internal_runs_api", required_scope="runs:write"
        )


def test_user_token_rejected_on_service_channel(broker):
    """A stolen mobile user token must never authenticate a service-to-service call."""
    cognito = auth.CognitoProvider()
    user_token = cognito.mint_token(
        user_id="usr_alice",
        email="alice@gmail.com",
        client_id="client_mobile_app",
        audience="internal_runs_api",
    )
    # Signed by the user pool key, not the broker key: provenance check fails.
    with pytest.raises(auth.WorkloadIdentityError):
        broker.verify_service_call(
            user_token, expected_audience="internal_runs_api", required_scope="runs:write"
        )


def test_wrong_audience_service_token_is_denied(broker):
    """A service token for one internal API cannot be replayed against another."""
    token = broker.exchange_token(
        "wearable-import-worker",
        "platform-attest-import-worker",
        audience="internal_runs_api",
        requested_scopes=["runs:write"],
    )
    with pytest.raises(auth.WorkloadIdentityError):
        broker.verify_service_call(
            token, expected_audience="internal_billing_api", required_scope="runs:write"
        )

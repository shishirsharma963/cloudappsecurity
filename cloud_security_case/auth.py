"""Authentication module simulating Cognito User Pool JWT minting and verification.

Uses asymmetric RS256 JWT validation. The private key remains within the provider
for minting tokens, while public keys are distributed to API Gateway / verifying nodes.
"""

import time
import uuid
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

_ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_fitnessapp"


class AuthenticationError(Exception):
    pass


class TokenRevokedError(AuthenticationError):
    """Raised when a token is cryptographically valid but has been revoked."""


class RevocationList:
    """Edge deny-list consulted on every request to revoke stateless JWTs.

    A signed JWT is valid until its `exp`; nothing in the signature can undo
    that. The classic answer is a deny-list keyed by the token id (`jti`) or
    user `sub` that the authorizer checks in-band. In production this is a
    low-latency cache (ElastiCache/DynamoDB) fed by the same revocation events
    that drive Cognito GlobalSignOut, so a stolen token dies in seconds
    instead of at TTL.

    Entries self-expire at the revoked token's original `exp`: once the token
    would have expired anyway, the deny-list no longer needs to carry it, so
    the structure stays bounded (mirrors a cache TTL).
    """

    def __init__(self):
        self._revoked_jti = {}  # jti -> expiry epoch
        self._revoked_subjects = {}  # sub -> (cutoff_epoch, expiry_epoch)

    def revoke_jti(self, jti: str, *, token_exp: int):
        """Revoke a single token by its unique id."""
        self._revoked_jti[jti] = token_exp

    def revoke_subject(self, sub: str, *, not_before: int | None = None, horizon: int | None = None):
        """Revoke all of a subject's tokens issued at/before `not_before`.

        Models Cognito AdminUserGlobalSignOut: tokens issued before the
        sign-out instant are rejected; tokens minted after a fresh re-auth are
        honored. `horizon` bounds how long the tombstone is retained.
        """
        cutoff = not_before if not_before is not None else int(time.time())
        expiry = horizon if horizon is not None else cutoff + 3600
        self._revoked_subjects[sub] = (cutoff, expiry)

    def is_revoked(self, claims: dict) -> bool:
        now = int(time.time())
        self._evict(now)

        jti = claims.get("jti")
        if jti in self._revoked_jti:
            return True

        sub_entry = self._revoked_subjects.get(claims.get("sub"))
        if sub_entry is not None:
            cutoff, _ = sub_entry
            # Tokens issued at or before the sign-out cutoff are dead;
            # a post-reauth token (iat after cutoff) is allowed through.
            if int(claims.get("iat", 0)) <= cutoff:
                return True
        return False

    def _evict(self, now: int):
        """Drop tombstones whose underlying tokens have already expired."""
        self._revoked_jti = {j: e for j, e in self._revoked_jti.items() if e > now}
        self._revoked_subjects = {
            s: v for s, v in self._revoked_subjects.items() if v[1] > now
        }


class CognitoProvider:
    def __init__(self):
        # Generate an RSA public/private key pair on startup
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def public_pem(self) -> bytes:
        """Get the public key in PEM format to distribute to API Gateway verifiers."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def mint_token(
        self,
        *,
        user_id: str,
        email: str,
        client_id: str,
        audience: str,
        ttl_seconds: int = 3600,
    ) -> str:
        """Mint a signed RS256 JWT token representing a Cognito Access/ID token."""
        now = int(time.time())
        payload = {
            "iss": _ISSUER,
            "sub": user_id,
            "email": email,
            "aud": audience,
            "client_id": client_id,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid.uuid4()),
            "token_use": "access",
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def verify_token(
        self,
        token: str,
        *,
        expected_audience: str,
        revocation_list: RevocationList | None = None,
    ) -> dict:
        """Cryptographically verify the token using the public key.

        When a `revocation_list` is supplied, the deny-list is consulted
        *after* signature validation (an attacker must not be able to probe
        revocation state with unsigned garbage). This is the stateless-vs-
        revocable compromise: the hot path stays a local cache lookup, and
        only revocation *events* touch shared state.
        """
        try:
            claims = jwt.decode(
                token,
                self.public_pem,
                algorithms=["RS256"],
                audience=expected_audience,
                options={"require": ["exp", "aud", "sub", "iss"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("token expired") from e
        except jwt.InvalidAudienceError as e:
            raise AuthenticationError(
                f"wrong audience: token not minted for '{expected_audience}'"
            ) from e
        except jwt.PyJWTError as e:
            raise AuthenticationError(f"invalid token signature: {e}") from e

        if revocation_list is not None and revocation_list.is_revoked(claims):
            raise TokenRevokedError(
                "token revoked: signature valid but jti/subject is on the deny-list"
            )
        return claims


# ---------------------------------------------------------------------------
# Workload identity plane (service-to-service)
#
# User tokens answer "which human is calling?"; they say nothing about which
# *service* is calling. A backend worker that forwards a user's token downstream
# creates a confused-deputy problem: the callee cannot tell the import worker
# from a stolen mobile token. The production answer is a token exchange —
# AWS STS AssumeRole or SPIFFE/SPIRE SVID issuance — where the platform attests
# the workload and a broker mints a short-lived, scoped service credential.
# ---------------------------------------------------------------------------

_WORKLOAD_ISSUER = "spiffe://fitnesslog.internal/identity-broker"
_WORKLOAD_TOKEN_TTL_SECONDS = 300  # short-lived by design, like STS session credentials


class WorkloadIdentityError(Exception):
    pass


class WorkloadIdentityBroker:
    """Simulates an STS AssumeRole / SPIFFE-SVID style token exchange.

    Workloads are registered with an attestation secret (standing in for the
    platform attestation AWS performs via instance identity documents or
    Lambda execution roles) and a fixed set of scopes. The broker exchanges a
    successful attestation for a short-lived RS256 service token whose
    `token_use` claim distinguishes it from user tokens.
    """

    def __init__(self):
        self._signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # workload_name -> {"attestation_secret": ..., "scopes": [...]}
        self._registry = {}

    @property
    def public_pem(self) -> bytes:
        """Public verification key distributed to callee services."""
        return self._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def register_workload(self, workload_name: str, *, attestation_secret: str, scopes: list):
        """Register a workload and the scopes it is allowed to be granted.

        Mirrors creating an IAM role with a trust policy: only the registered
        principal may assume it, and the attached policy caps what it can do.
        """
        self._registry[workload_name] = {
            "attestation_secret": attestation_secret,
            "scopes": list(scopes),
        }

    def exchange_token(
        self,
        workload_name: str,
        attestation_secret: str,
        *,
        audience: str,
        requested_scopes: list,
    ) -> str:
        """Exchange a workload attestation for a short-lived scoped service token.

        Denies unregistered workloads, failed attestations, and scope escalation
        (requesting scopes beyond the workload's registration) — the same checks
        STS applies via role trust policies and session policies.
        """
        entry = self._registry.get(workload_name)
        if entry is None:
            raise WorkloadIdentityError(f"unknown workload '{workload_name}': no trust registration")
        if attestation_secret != entry["attestation_secret"]:
            raise WorkloadIdentityError(f"attestation failed for workload '{workload_name}'")

        granted = set(entry["scopes"])
        escalation = set(requested_scopes) - granted
        if escalation:
            raise WorkloadIdentityError(
                f"scope escalation denied for '{workload_name}': "
                f"requested {sorted(escalation)} beyond registered scopes {sorted(granted)}"
            )

        now = int(time.time())
        payload = {
            "iss": _WORKLOAD_ISSUER,
            "sub": f"spiffe://fitnesslog.internal/workload/{workload_name}",
            "aud": audience,
            "iat": now,
            "exp": now + _WORKLOAD_TOKEN_TTL_SECONDS,
            "jti": str(uuid.uuid4()),
            "token_use": "workload",
            "scope": " ".join(sorted(requested_scopes)),
        }
        return jwt.encode(payload, self._signing_key, algorithm="RS256")

    def verify_service_call(
        self, token: str, *, expected_audience: str, required_scope: str
    ) -> dict:
        """Callee-side verification of a service-to-service credential.

        Enforces provenance (signature + issuer), audience binding, expiry,
        the `token_use=workload` claim (a user token — even a validly signed
        one — must never authenticate a service call), and the required scope.
        """
        try:
            claims = jwt.decode(
                token,
                self.public_pem,
                algorithms=["RS256"],
                audience=expected_audience,
                issuer=_WORKLOAD_ISSUER,
                options={"require": ["exp", "aud", "sub", "iss"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise WorkloadIdentityError("service token expired") from e
        except jwt.PyJWTError as e:
            raise WorkloadIdentityError(f"service token rejected: {e}") from e

        if claims.get("token_use") != "workload":
            raise WorkloadIdentityError(
                "confused deputy blocked: token is not a workload credential "
                f"(token_use='{claims.get('token_use')}')"
            )

        granted_scopes = set(claims.get("scope", "").split())
        if required_scope not in granted_scopes:
            raise WorkloadIdentityError(
                f"insufficient scope: call requires '{required_scope}', "
                f"token grants {sorted(granted_scopes)}"
            )
        return claims

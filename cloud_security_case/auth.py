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

    def verify_token(self, token: str, *, expected_audience: str) -> dict:
        """Cryptographically verify the token using the public key."""
        try:
            return jwt.decode(
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

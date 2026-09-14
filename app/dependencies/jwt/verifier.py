import logging

import jwt
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from fastapi import Request, HTTPException

from app.config import settings
from app.dependencies.jwt.exceptions.jwt_exceptions import InvalidJWTSignatureError, NotSupportedJWTAlgorithmError, \
    UnexpectedJWTDecodingError, EB401Error
from app.dependencies.jwt.x5u import veify_x5u_safety_and_get_from_url
from app.dependencies.jwt.initial_structure_validator import validate_auth_header_and_claimedset_structur

logger = logging.getLogger(__name__)


def verify_jwt(request: Request) -> None:
    try:
        # first, it is verified the general structure of the jwt token and auth header is correct.
        auth_header = request.headers.get("Authorization")
        decoded_token, jwt_token = validate_auth_header_and_claimedset_structur(auth_header=auth_header)

        # the general structure seems fine, safety of x5u is checked and then downloaded
        public_key = veify_x5u_safety_and_get_from_url(x5u=decoded_token['header']['x5u'])

        # verify public key against the jwt token
        _verify_claimed_set_against_public_key(token=jwt_token, public_key=public_key)
        sad
    except EB401Error:
        raise
    except Exception:
        logger.exception("Unexpected error while verifying JWT")
        raise HTTPException(
            status_code=500, detail="Unhandled error while verifying JWT"
        )


def _verify_claimed_set_against_public_key(token: str, public_key: CertificatePublicKeyTypes) -> None:
    try:
        jwt.decode(token, public_key, algorithms=[settings.allowed_algorithm])
    except jwt.exceptions.InvalidSignatureError:
        raise InvalidJWTSignatureError()
    except jwt.exceptions.InvalidAlgorithmError:
        raise NotSupportedJWTAlgorithmError()
    except jwt.exceptions.PyJWTError:
        raise UnexpectedJWTDecodingError()
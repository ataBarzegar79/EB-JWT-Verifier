import jwt
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from app.dependencies.jwt.jwt_exceptions import NotSupportedJWTAlgorithmError, \
    UnexpectedJWTDecodingError, InvalidJWTSignatureError


def verify_claimed_set_against_public_key(token: str, public_key: CertificatePublicKeyTypes) -> None:
    try:
        jwt.decode(token, public_key, algorithms=["RS256"])
    except jwt.exceptions.InvalidSignatureError:
        raise InvalidJWTSignatureError()
    except jwt.exceptions.InvalidAlgorithmError:
        raise NotSupportedJWTAlgorithmError()
    except jwt.exceptions.InvalidTokenError:
        raise UnexpectedJWTDecodingError()

import jwt
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes


def verify_claimed_set_against_public_key(token: str, public_key: CertificatePublicKeyTypes) -> None:
    try:
        jwt.decode(token, public_key, algorithms=["RS256"])
    except jwt.exceptions.InvalidSignatureError:
        raise HTTPException(status_code=400, detail="JWT token signature is invalid.")
    except jwt.exceptions.InvalidAlgorithmError:
        raise HTTPException(status_code=400, detail="JWT token algorithm is not supported.")
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=400, detail="JWT token has an unexpected failure.")

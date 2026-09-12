import jwt
from fastapi import HTTPException


def _fail_if_haeder_is_wrong(jwt_header: dict):
    algorithm = jwt_header.get("alg")
    typ = jwt_header.get("typ")
    if algorithm != "RS256":
        raise HTTPException(status_code=400, detail="Token algorithm is not supported.")
    if typ != "JWT":
        raise HTTPException(status_code=400, detail="Token type is not supported.")


def check_header_and_payload(auth_header: str):
    jwt_token = auth_header.split()[1]
    try:
        decoded_token = jwt.decode_complete(jwt_token, options={
            "verify_signature": False,
            "verify_exp": True,
            "verify_iat": True,
            "require": ["exp", "iat", "x5u"],
        })
    except jwt.exceptions.DecodeError:
        raise HTTPException(status_code=400, detail="Token Format is not valid JWT.")
    except jwt.exceptions.MissingRequiredClaimError:
        raise HTTPException(status_code=400, detail="Required claim is missing: exp, iat, x5u")
    except jwt.exceptions.InvalidIssuedAtError:
        raise HTTPException(status_code=400, detail="iat is not numeric.")
    except jwt.exceptions.ImmatureSignatureError:
        raise HTTPException(status_code=400, detail="iat is in future.")
    except jwt.exceptions.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="exp has expired.")
    except jwt.exceptions.InvalidTokenError:
        raise HTTPException(status_code=400, detail="JWT token has an unexpected failure.")

    jwt_header = decoded_token.get("header")
    _fail_if_haeder_is_wrong(jwt_header=jwt_header)

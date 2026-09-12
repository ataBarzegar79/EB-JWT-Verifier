from fastapi import HTTPException
import jwt


def _fail_if_header_is_none(auth_header: str | None) -> None:
    if auth_header is None:
        raise HTTPException(status_code=401, detail='Authorization header is missing')


def _fail_if_header_structure_is_wrong(auth_header: str) -> None:
    parts = auth_header.split()
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail='Authorization header must be' + '"Bearer <token>".')
    if parts[0].lower() != "bearer":
        raise HTTPException(status_code=400, detail='Authorization header must start with Bearer.')
    try:
        jwt.decode(parts[1], options={"verify_signature": False})
    except jwt.PyJWTError:
        raise HTTPException(status_code=400, detail='JWT token is cannot be decoded.')


def check_auth_header_structure(auth_header: str | None) -> None:
    _fail_if_header_is_none(auth_header)
    _fail_if_header_structure_is_wrong(auth_header)

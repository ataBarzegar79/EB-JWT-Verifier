from fastapi import HTTPException


def _fail_if_header_is_none(auth_header: str | None) -> None:
    if auth_header is None:
        raise HTTPException(status_code=401, detail='Authorization header is missing')


def _fail_if_header_structure_is_wrong(auth_header: str) -> None:
    parts = auth_header.split()
    if len(parts) != 2:
        raise HTTPException(status_code=400, detail='Authorization header must be' + '"Bearer <token>".')
    if parts[0].lower() != "bearer":
        raise HTTPException(status_code=400, detail='Authorization header must start with Bearer.')
    token_parts = parts[1].split(".")
    if len(token_parts) != 3:
        raise HTTPException(status_code=400, detail='JWT token is cannot be decoded. Make sure it follows the '
                                                    'structure: header.payload.signature all in base64url encoded '
                                                    'format.')
    for part in token_parts:
        if len(part) % 4 != 0 or len(part) == 0:
            raise HTTPException(status_code=400, detail='JWT token is cannot be decoded. Header, payload or Signature '
                                                        'is not Base64 encoded.')


def check_authorization_header_structure(auth_header: str | None) -> str:
    _fail_if_header_is_none(auth_header)
    _fail_if_header_structure_is_wrong(auth_header)
    return auth_header[1]

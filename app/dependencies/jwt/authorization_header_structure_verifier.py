from app.dependencies.jwt.jwt_exceptions import AuthHeaderMissingError, AuthHeaderInvalidFormatError, \
    AuthHeaderMissingBearerError, AuthHeaderInvalidJWTTokenFormatError


def _fail_if_header_is_none(auth_header: str | None) -> None:
    if auth_header is None:
        raise AuthHeaderMissingError()


def _fail_if_header_structure_is_wrong(auth_header: str) -> None:
    parts = auth_header.split()
    if len(parts) != 2:
        raise AuthHeaderInvalidFormatError()
    if parts[0].lower() != "bearer":
        raise AuthHeaderMissingBearerError()
    token_parts = parts[1].split(".")
    if len(token_parts) != 3:
        raise AuthHeaderInvalidJWTTokenFormatError()


def check_authorization_header_structure(auth_header: str | None) -> str:
    _fail_if_header_is_none(auth_header)
    _fail_if_header_structure_is_wrong(auth_header)
    return auth_header.split()[1]

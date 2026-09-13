from fastapi import HTTPException


# 400 errors

class EB400Error(HTTPException):
    status_code = 400

    def __init__(self, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=self.status_code, detail=detail, headers=headers)


class AuthHeaderInvalidFormatError(EB400Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header must be' + '"Bearer <token>".')


class AuthHeaderMissingBearerError(EB400Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header must start with Bearer.')


class AuthHeaderInvalidJWTTokenFormatError(EB400Error):
    def __init__(self) -> None:
        super().__init__(detail='JWT token is cannot be decoded. Make sure it follows the '
                                'structure: header.payload.signature all in base64url encoded '
                                'format.')


class InvalidJWTTokenFormatError(EB400Error):
    def __init__(self):
        super().__init__(detail='Token Format is not valid JWT.')


class MissingRequiredClaimError(EB400Error):
    def __init__(self):
        super().__init__(detail='Required claim is missing: exp, iat, x5u')


class NonNumericIatError(EB400Error):
    def __init__(self):
        super().__init__(detail='iat is not numeric.')


class ImmatureIatError(EB400Error):
    def __init__(self):
        super().__init__(detail='iat is in future.')


class ExpiredSignatureError(EB400Error):
    def __init__(self):
        super().__init__(detail='exp has expired.')


class UnexpectedJWTDecodingError(EB400Error):
    def __init__(self):
        super().__init__(detail='JWT token has an unexpected failure.')


class NotSupportedJWTAlgorithmError(EB400Error):
    def __init__(self):
        super().__init__(detail='Token algorithm is not supported.')


class NonJWTTypeError(EB400Error):
    def __init__(self):
        super().__init__(detail='Token type is not supported.')


class InvalidJWTSignatureError(EB400Error):
    def __init__(self):
        super().__init__(detail='JWT token signature is invalid.')


class NonHTTPSProtocolError(EB400Error):
    def __init__(self):
        super().__init__(detail='x5u does not support HTTPS protocol.')


class WrongX5UPortError(EB400Error):
    def __init__(self):
        super().__init__(detail='x5u does not support non-443 port and not a trusted url.')


class X5UNonStringError(EB400Error):
    def __init__(self):
        super().__init__(detail='x5u is not string.')


# 401 errors
class EB401Error(HTTPException):
    status_code = 401

    def __init__(self, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=self.status_code, detail=detail, headers=headers)


class AuthHeaderMissingError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header is missing')


# 5XX errors
class X5UUrlUnreachableError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=503, detail='x5u url is timed out or unreachable.')


class X5UUrlErroredResponseError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=502, detail='Specified x5u url responded with an error.')


class Invalid509EncodedCertificateError(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=502, detail='Specified x5u file is not a valid x509 PEM encoded data.')

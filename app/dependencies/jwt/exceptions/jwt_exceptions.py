from fastapi import HTTPException


class EB401Error(HTTPException):
    status_code = 401

    def __init__(self, detail: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(status_code=self.status_code, detail=detail, headers=headers)


class AuthHeaderInvalidFormatError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header must be' + '"Bearer <token>".')


class AuthHeaderMissingBearerError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header must start with Bearer.')


class AuthHeaderInvalidJWTTokenFormatError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='JWT token is cannot be decoded. Make sure it follows the '
                                'structure: header.payload.signature all in base64url encoded '
                                'format.')


class InvalidJWTTokenFormatError(EB401Error):
    def __init__(self):
        super().__init__(detail='Token Format is not valid JWT.')


class MissingRequiredClaimError(EB401Error):
    def __init__(self):
        super().__init__(detail='Required claim is missing: exp, iat, x5u')


class NonNumericIatError(EB401Error):
    def __init__(self):
        super().__init__(detail='iat is not numeric.')


class ImmatureIatError(EB401Error):
    def __init__(self):
        super().__init__(detail='iat is in future.')


class ExpiredSignatureError(EB401Error):
    def __init__(self):
        super().__init__(detail='exp has expired.')


class UnexpectedJWTDecodingError(EB401Error):
    def __init__(self):
        super().__init__(detail='JWT token has an unexpected failure.')


class NotSupportedJWTAlgorithmError(EB401Error):
    def __init__(self):
        super().__init__(detail='Token algorithm is not supported.')


class NonJWTTypeError(EB401Error):
    def __init__(self):
        super().__init__(detail='Token type is not supported.')


class InvalidJWTSignatureError(EB401Error):
    def __init__(self):
        super().__init__(detail='JWT token signature is invalid.')


class X5UNonStringError(EB401Error):
    def __init__(self):
        super().__init__(detail='x5u is not string.')


class AuthHeaderMissingError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Authorization header is missing')


class X5UUrlUnreachableError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='x5u url is timed out or unreachable.')


class X5UUrlErroredResponseError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Specified x5u url responded with an error.')


class Invalid509EncodedCertificateError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='Specified x5u file is not a valid x509 PEM encoded data.')


class X5uURLNotEligibleError(EB401Error):
    def __init__(self) -> None:
        super().__init__(detail='The specified x5u Url is not verified in the system.')

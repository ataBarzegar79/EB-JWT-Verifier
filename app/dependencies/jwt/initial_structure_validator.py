import jwt

from app.config import settings
from app.dependencies.jwt.exceptions.jwt_exceptions import AuthHeaderMissingError, AuthHeaderInvalidFormatError, \
    AuthHeaderMissingBearerError, AuthHeaderInvalidJWTTokenFormatError, InvalidJWTTokenFormatError, \
    MissingRequiredClaimError, \
    NonNumericIatError, ImmatureIatError, ExpiredSignatureError, UnexpectedJWTDecodingError, \
    NotSupportedJWTAlgorithmError, NonJWTTypeError


def validate_auth_header_and_claimedset_structur(auth_header: str | None):
    """
    This is a very general check for the jwt checker engine.

    1. First, the Authorization header is checked for the correct format.
    2. Then, the header and payload from the claimedet are checked for the correct format.
    This is done before even collecting the public key since most of the users are not considered attakers, so
    the wors case scenario is kept for the next stage. This way, the consumed time over the network is saved.
    And most checks are done before trusting an endpoint, and dummy errors can be caught.

    """
    jwt_token = check_authorization_header_structure(auth_header=auth_header)
    decoded_token = check_header_and_payload(jwt_token=jwt_token)
    return decoded_token, jwt_token


def check_authorization_header_structure(auth_header: str | None) -> str:
    if auth_header is None:
        raise AuthHeaderMissingError()
    parts = auth_header.split()
    if len(parts) != 2:
        raise AuthHeaderInvalidFormatError()
    if parts[0].lower() != 'bearer':
        raise AuthHeaderMissingBearerError()
    token_parts = parts[1].split(".")
    if len(token_parts) != 3:
        raise AuthHeaderInvalidJWTTokenFormatError()

    return auth_header.split()[1]


def check_header_and_payload(jwt_token: str) -> dict:
    try:
        decoded_token = jwt.decode_complete(jwt_token, options={
            'verify_signature': False,
            'verify_exp': True,
            'verify_iat': True,
            'require': ['exp', 'iat'],
        })
    except jwt.exceptions.DecodeError:
        raise InvalidJWTTokenFormatError()
    except jwt.exceptions.MissingRequiredClaimError:
        raise MissingRequiredClaimError()
    except jwt.exceptions.InvalidIssuedAtError:
        raise NonNumericIatError()
    except jwt.exceptions.ImmatureSignatureError:
        raise ImmatureIatError()
    except jwt.exceptions.ExpiredSignatureError:
        raise ExpiredSignatureError()
    except jwt.exceptions.PyJWTError:
        raise UnexpectedJWTDecodingError()

    jwt_header = decoded_token.get('header')
    algorithm = jwt_header.get('alg')
    typ = jwt_header.get('typ')
    x5u = jwt_header.get('x5u')
    if algorithm != settings.allowed_algorithm:
        raise NotSupportedJWTAlgorithmError()
    if typ != settings.allowed_type:
        raise NonJWTTypeError()
    if x5u is None:
        raise MissingRequiredClaimError()

    return decoded_token

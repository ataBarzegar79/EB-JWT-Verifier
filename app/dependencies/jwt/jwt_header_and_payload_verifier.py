import jwt

from app.dependencies.jwt.jwt_exceptions import InvalidJWTTokenFormatError, MissingRequiredClaimError, \
    NonNumericIatError, ImmatureIatError, ExpiredSignatureError, UnexpectedJWTDecodingError, \
    NotSupportedJWTAlgorithmError, NonJWTTypeError


def _fail_if_haeder_is_wrong(jwt_header: dict):
    algorithm = jwt_header.get('alg')
    typ = jwt_header.get('typ')
    x5u = jwt_header.get('x5u')
    if algorithm != 'RS256':
        raise NotSupportedJWTAlgorithmError()
    if typ != "JWT":
        raise NonJWTTypeError()
    if x5u is None:
        raise MissingRequiredClaimError()


def check_header_and_payload(jwt_token: str) -> dict:
    try:
        decoded_token = jwt.decode_complete(jwt_token, options={
            'verify_signature': False,
            'verify_exp': True,
            'verify_iat': True,
            'require': ['exp', 'iat'],  # todo: add to settings
        })
        print(decoded_token)
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
    except jwt.exceptions.InvalidTokenError:
        raise UnexpectedJWTDecodingError()

    jwt_header = decoded_token.get("header")
    _fail_if_haeder_is_wrong(jwt_header=jwt_header)

    return decoded_token

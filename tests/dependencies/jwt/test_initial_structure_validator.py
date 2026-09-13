import time
import pytest

from tests.dependencies.jwt.factory.jwt_factory import FakeJwtFactory
from app.dependencies.jwt.initial_structure_validator import check_header_and_payload, \
    check_authorization_header_structure
from app.dependencies.jwt.exceptions.jwt_exceptions import AuthHeaderMissingError, AuthHeaderInvalidFormatError, \
    AuthHeaderMissingBearerError, AuthHeaderInvalidJWTTokenFormatError, NonJWTTypeError, NotSupportedJWTAlgorithmError, \
    ExpiredSignatureError, \
    ImmatureIatError, NonNumericIatError, MissingRequiredClaimError, InvalidJWTTokenFormatError


def test_missing_auth_header_fails():
    with pytest.raises(AuthHeaderMissingError):
        check_authorization_header_structure(auth_header=None)


def test_wrong_structure_for_header_fails():
    with pytest.raises(AuthHeaderInvalidFormatError):
        check_authorization_header_structure(auth_header=";ldsf,")


def test_auth_header_fails_if_not_bearer():
    with pytest.raises(AuthHeaderMissingBearerError):
        check_authorization_header_structure(auth_header="another token")


def test_auth_header_fails_if_token_missing_parts():
    with pytest.raises(AuthHeaderInvalidJWTTokenFormatError):
        check_authorization_header_structure(auth_header="Bearer A.B")


def test_failed_jwt_structure_fails():
    jwt = FakeJwtFactory().update_headers("missing_header").make()

    with pytest.raises(InvalidJWTTokenFormatError):
        check_header_and_payload(jwt)


def test_missing_claim_fails():
    jwt = FakeJwtFactory().update_payloads({"iat": time.time()}).make()

    with pytest.raises(MissingRequiredClaimError):
        check_header_and_payload(jwt)


def test_iat_fails_if_non_numeric():
    jwt = FakeJwtFactory().update_payload("iat", "non_nnumeric").make()

    with pytest.raises(NonNumericIatError):
        check_header_and_payload(jwt)


def test_future_iat_fails():
    jwt = FakeJwtFactory().update_payload("iat", time.time() + 10).make()

    with pytest.raises(ImmatureIatError):
        check_header_and_payload(jwt)


def test_expired_jwt_fails():
    jwt = FakeJwtFactory().update_payload("exp", time.time() - 10).make()
    with pytest.raises(ExpiredSignatureError):
        check_header_and_payload(jwt)


def test_non_jwt_in_header_fails():
    jwt = FakeJwtFactory().update_header('typ', "fake").make()
    with pytest.raises(NonJWTTypeError):
        check_header_and_payload(jwt)


def test_non_rs256_in_header_fails():
    jwt = FakeJwtFactory().update_header('alg', "HS256").make()
    with pytest.raises(NotSupportedJWTAlgorithmError):
        check_header_and_payload(jwt)

import time

import pytest

from app.dependencies.jwt.jwt_exceptions import NonJWTTypeError, NotSupportedJWTAlgorithmError, ExpiredSignatureError, \
    ImmatureIatError, NonNumericIatError, MissingRequiredClaimError, InvalidJWTTokenFormatError
from app.dependencies.jwt.jwt_header_and_payload_verifier import check_header_and_payload
from tests.dependencies.jwt.factory.jwt_factory import FakeJwtFactory


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

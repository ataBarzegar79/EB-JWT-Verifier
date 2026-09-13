import time

import pytest
from fastapi import HTTPException

from app.dependencies.jwt.jwt_header_and_payload_verifier import check_header_and_payload
from tests.dependencies.jwt.factory.jwt_factory import FakeJwtFactory


def test_failed_jwt_structure_fails():
    jwt = FakeJwtFactory().update_headers("missing_header").make()

    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)

    assert exception.value.status_code == 400
    assert exception.value.detail == "Token Format is not valid JWT."


def test_missing_claim_fails():
    jwt = FakeJwtFactory().update_payloads({"iat": time.time()}).make()

    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)
    assert exception.value.status_code == 400
    assert exception.value.detail == "Required claim is missing: exp, iat, x5u"


def test_iat_fails_if_non_numeric():
    jwt = FakeJwtFactory().update_payload("iat", "non_nnumeric").make()

    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)

    assert exception.value.status_code == 400
    assert exception.value.detail == "iat is not numeric."


def test_future_iat_fails():
    jwt = FakeJwtFactory().update_payload("iat", time.time() + 10).make()

    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)

    assert exception.value.status_code == 400
    assert exception.value.detail == "iat is in future."


def test_expired_jwt_fails():
    jwt = FakeJwtFactory().update_payload("exp", time.time() - 10).make()
    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)
    assert exception.value.status_code == 400
    assert exception.value.detail == "exp has expired."


def test_non_jwt_in_header_fails():
    jwt = FakeJwtFactory().update_header('alg', "fake").make()
    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)
    assert exception.value.status_code == 400
    assert exception.value.detail == "Token algorithm is not supported."


def test_non_rs256_in_header_fails():
    jwt = FakeJwtFactory().update_header('alg', "HS256").make()
    with pytest.raises(HTTPException) as exception:
        check_header_and_payload(jwt)
        assert exception.value.status_code == 400
        assert exception.value.detail == "Token algorithm is not supported."

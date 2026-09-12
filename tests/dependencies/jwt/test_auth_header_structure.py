from fastapi import HTTPException
import pytest


from app.dependencies.jwt.auth_header_structure import check_auth_header_structure


def test_missing_auth_header_fails():
    with pytest.raises(HTTPException) as exception:
        check_auth_header_structure(auth_header=None)
    assert exception.value.status_code == 401
    assert exception.value.detail == 'Authorization header is missing'


def test_wrong_structure_for_header_fails():
    with pytest.raises(HTTPException) as exception:
        check_auth_header_structure(auth_header=";ldsf,")
    assert exception.value.status_code == 400
    assert exception.value.detail == 'Authorization header must be' + '"Bearer <token>".'


def test_auth_header_fails_if_not_bearer():
    with pytest.raises(HTTPException) as exception:
        check_auth_header_structure(auth_header="another token")
    assert exception.value.status_code == 400
    assert exception.value.detail == 'Authorization header must start with Bearer.'


def test_auth_header_fails_if_token_is_invalid():
    with pytest.raises(HTTPException) as exception:
        check_auth_header_structure(auth_header="Bearer invalid_token")
        assert exception.value.status_code == 400
        assert exception.value.detail == 'JWT token is cannot be decoded.'

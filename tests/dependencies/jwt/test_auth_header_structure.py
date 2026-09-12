from fastapi import HTTPException
import pytest

from app.dependencies.jwt.authorization_header_structure import check_authorization_header_structure


def test_missing_auth_header_fails():
    with pytest.raises(HTTPException) as exception:
        check_authorization_header_structure(auth_header=None)
    assert exception.value.status_code == 401
    assert exception.value.detail == 'Authorization header is missing'


def test_wrong_structure_for_header_fails():
    with pytest.raises(HTTPException) as exception:
        check_authorization_header_structure(auth_header=";ldsf,")
    assert exception.value.status_code == 400
    assert exception.value.detail == 'Authorization header must be' + '"Bearer <token>".'


def test_auth_header_fails_if_not_bearer():
    with pytest.raises(HTTPException) as exception:
        check_authorization_header_structure(auth_header="another token")
    assert exception.value.status_code == 400
    assert exception.value.detail == 'Authorization header must start with Bearer.'


def test_auth_header_fails_if_token_is_invalid():
    with pytest.raises(HTTPException) as exception:
        check_authorization_header_structure(auth_header="Bearer A.B.C")
    assert exception.value.status_code == 400
    assert exception.value.detail == ('JWT token is cannot be decoded. Header, payload or Signature is not Base64 '
                                      'encoded.')


def test_auth_header_fails_if_token_missing_parts():
    with pytest.raises(HTTPException) as exception:
        check_authorization_header_structure(auth_header="Bearer A.B")
    assert exception.value.status_code == 400
    assert exception.value.detail == ('JWT token is cannot be decoded. Make sure it follows the '
                                      'structure: header.payload.signature all in base64url encoded '
                                      'format.')

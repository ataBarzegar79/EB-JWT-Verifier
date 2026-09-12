import pytest
from fastapi import HTTPException

from app.dependencies.jwt.x5u_verifier import check_x5u_validity_and_safety


def test_non_string_x5u_fails():
    with pytest.raises(HTTPException) as exception:
        check_x5u_validity_and_safety(x5u=123)
    assert exception.value.status_code == 400
    assert exception.value.detail == "x5u is not string."


def test_non_listed_x5u_with_non_https_fails():
    with pytest.raises(HTTPException) as exception:
        check_x5u_validity_and_safety(x5u="http://www.example.com")
    assert exception.value.status_code == 400
    assert exception.value.detail == "x5u does not support HTTPS protocol."


def test_non_listed_x5u_with_non_443_port_fails():
    with pytest.raises(HTTPException) as exception:
        check_x5u_validity_and_safety(x5u="https://www.example.com:8080")
    assert exception.value.status_code == 400
    assert exception.value.detail == "x5u does not support non-443 port and not a trusted url."

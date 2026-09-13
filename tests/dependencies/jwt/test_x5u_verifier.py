import pytest

from app.dependencies.jwt.jwt_exceptions import WrongX5UPortError, NonHTTPSProtocolError, X5UNonStringError
from app.dependencies.jwt.x5u_verifier import check_x5u_validity_and_safety


def test_non_string_x5u_fails():
    with pytest.raises(X5UNonStringError):
        check_x5u_validity_and_safety(x5u=123)


def test_non_listed_x5u_with_non_https_fails():
    with pytest.raises(NonHTTPSProtocolError):
        check_x5u_validity_and_safety(x5u="http://www.example.com")


def test_non_listed_x5u_with_non_443_port_fails():
    with pytest.raises(WrongX5UPortError):
        check_x5u_validity_and_safety(x5u="https://www.example.com:8080")

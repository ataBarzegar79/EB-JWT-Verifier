import pytest

from app.dependencies.jwt.authorization_header_structure_verifier import check_authorization_header_structure
from app.dependencies.jwt.jwt_exceptions import AuthHeaderMissingError, AuthHeaderInvalidFormatError, \
    AuthHeaderMissingBearerError, AuthHeaderInvalidJWTTokenFormatError


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

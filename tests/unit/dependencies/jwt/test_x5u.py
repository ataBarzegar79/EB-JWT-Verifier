from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse

import pytest
import requests
from cryptography import x509

from app.dependencies.jwt.exceptions.jwt_exceptions import Invalid509EncodedCertificateError, \
    X5UUrlErroredResponseError, \
    X5UUrlUnreachableError, X5UNonStringError, X5uURLNotEligibleError
from app.dependencies.jwt.x5u import _check_x5u_validity_and_safety, _get_public_key_from_url

fake_url = urlparse('https://www.fakeurl.com/certificate.pem')


# mockery object for the api call
@pytest.fixture
def request_mock():
    with patch('app.dependencies.jwt.x5u.requests.get') as mock:
        response = MagicMock()
        response.raise_for_status.return_value = None
        response.is_redirect = False
        mock.return_value.__enter__.return_value = response
        yield mock, response


def get_fake_certificate():
    certificates_path = Path(__file__).parents[3] / 'fake_files' / 'fake_certificate.pem'
    with open(certificates_path, 'rb') as f:
        return f.read()


@pytest.mark.parametrize('error', [requests.ConnectionError(), requests.Timeout()])
def test_unreachable_url_fails(request_mock, error):
    mock, response = request_mock
    mock.side_effect = error

    with pytest.raises(X5UUrlUnreachableError):
        _get_public_key_from_url(fake_url)


@pytest.mark.parametrize('error', [requests.HTTPError()])
def test_unseccsful_response_from_the_url_fails(request_mock, error):
    mock, response = request_mock
    response.raise_for_status.side_effect = requests.HTTPError('500 Server Error')

    with pytest.raises(X5UUrlErroredResponseError):
        _get_public_key_from_url(fake_url)


def test_redirect_response_fails(request_mock):
    mock, response = request_mock
    response.is_redirect = True

    with pytest.raises(X5uURLNotEligibleError):
        _get_public_key_from_url(fake_url)


@pytest.mark.parametrize('error', [ValueError()])
def test_invalid_certificate_content_fails(request_mock, error):
    mock, response = request_mock
    response.raw.read.return_value = b'a wrong certificate'

    with pytest.raises(Invalid509EncodedCertificateError):
        _get_public_key_from_url(fake_url)


def test_valid_certificate_returns_public_key(request_mock):
    mock, response = request_mock
    pem = get_fake_certificate()
    response.raw.read.return_value = pem

    public_key = _get_public_key_from_url(fake_url)
    expected = x509.load_pem_x509_certificate(pem).public_key()

    assert public_key.public_numbers() == expected.public_numbers()
    response.raw.read.assert_called_once_with(decode_content=True)


def test_non_string_x5u_fails():
    with pytest.raises(X5UNonStringError):
        _check_x5u_validity_and_safety(x5u=123)

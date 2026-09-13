from pathlib import Path
from unittest.mock import patch, MagicMock
from urllib.parse import urlparse

import pytest
import requests
from cryptography import x509
from fastapi import HTTPException

from app.dependencies.jwt.x5u_url_fetcher import get_public_key_from_url

fake_url = urlparse('https://www.fakeurl.com/certificate.pem')


# mockery object for the api call
@pytest.fixture
def request_mock():
    with patch('app.dependencies.jwt.x5u_url_fetcher.requests.get') as mock:
        response = MagicMock()
        response.raise_for_status.return_value = None
        mock.return_value.__enter__.return_value = response
        yield mock, response


def get_fake_certificate():
    certificates_path = Path(__file__).parent / 'fake_files' / 'fake_certificate.pem'
    with open(certificates_path, 'rb') as f:
        return f.read()


@pytest.mark.parametrize('error', [requests.ConnectionError(), requests.Timeout()])
def test_unreachable_url_fails(request_mock, error):
    mock, response = request_mock
    mock.side_effect = error

    with pytest.raises(HTTPException) as exception:
        get_public_key_from_url(fake_url)

    assert exception.value.status_code == 503
    assert exception.value.detail == 'x5u url is timed out or unreachable.'


@pytest.mark.parametrize('error', [requests.HTTPError()])
def test_unseccsful_response_from_the_url_fails(request_mock, error):
    mock, response = request_mock
    response.raise_for_status.side_effect = requests.HTTPError('500 Server Error')

    with pytest.raises(HTTPException) as exception:
        get_public_key_from_url(fake_url)

    assert exception.value.status_code == 502
    assert exception.value.detail == 'Specified x5u url responded with an error.'


@pytest.mark.parametrize('error', [ValueError()])
def test_unseccsful_response_from_the_url_fails(request_mock, error):
    mock, response = request_mock
    response.raw.read.return_value = b'a wrong certificate'

    with pytest.raises(HTTPException) as exception:
        get_public_key_from_url(fake_url)

    assert exception.value.status_code == 502
    assert exception.value.detail == 'Specified x5u file is not a valid x509 PEM encoded data.'


def test_valid_certificate_returns_public_key(request_mock):
    mock, response = request_mock
    pem = get_fake_certificate()
    response.raw.read.return_value = pem

    public_key = get_public_key_from_url(fake_url)
    expected = x509.load_pem_x509_certificate(pem).public_key()

    assert public_key.public_numbers() == expected.public_numbers()

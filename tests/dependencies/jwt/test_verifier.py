import time
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

import jwt
import pytest
from fastapi import Request

from app.dependencies.jwt.verifier import verify_jwt, _verify_claimed_set_against_public_key
from app.dependencies.jwt.exceptions.jwt_exceptions import NotSupportedJWTAlgorithmError, InvalidJWTSignatureError


@pytest.fixture(scope='module')
def _prepare_valid_rsa_key() -> tuple[bytes, bytes]:
    certificates_path = Path(__file__).parent / 'fake_files'
    return (
        (certificates_path / 'fake_private.pem').read_bytes(),
        (certificates_path / 'fake_certificate.pem').read_bytes(),
    )


def _prepare_fake_fast_apI_request_object(token) -> Request:
    bearer_token = f'Bearer {token}'
    return Request({
        'type': 'http',
        'headers': [(b'authorization', bearer_token.encode())],
    })


def test_jwt_verifier_succeeds(_prepare_valid_rsa_key):
    private_pem, public_pem = _prepare_valid_rsa_key
    public_pem = x509.load_pem_x509_certificate(public_pem).public_key()

    now = int(time.time())

    payload = {
        'iat': now - 10,
        'exp': now + 10,
    }
    header = {
        'alg': 'RS256',
        'typ': 'JWT',
        'x5u': 'https://example.com/certs.pem'
    }

    token = jwt.encode(
        payload,
        private_pem,
        algorithm='RS256',
        headers=header,
    )

    fake_request = _prepare_fake_fast_apI_request_object(token=token)

    with (
        patch('app.dependencies.jwt.x5u.x5u_allowed_hosts', [header['x5u']]),
        patch(
            'app.dependencies.jwt.x5u._get_public_key_from_url',
            return_value=public_pem
        ) as mock_fetch,
    ):
        verify_jwt(request=fake_request)
    mock_fetch.assert_called_once()


def test_wrong_token_and_wrong_key_public_key_raises_exception():
    with pytest.raises(InvalidJWTSignatureError):
        fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake_key_two = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode({'user': 'ata'}, fake_key_two, algorithm='RS256')

        _verify_claimed_set_against_public_key(token, fake_key.public_key())


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_wrong_public_key_algorithm_raises_exception():
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({'user': 'ata'}, "fake secret", algorithm='HS256')

    with pytest.raises(NotSupportedJWTAlgorithmError):
        _verify_claimed_set_against_public_key(token, fake_key.public_key())


def test_correct_token_and_correct_key_public_key_does_not_raise_exception():
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({'user': 'ata'}, fake_key, algorithm='RS256')

    _verify_claimed_set_against_public_key(token, fake_key.public_key())

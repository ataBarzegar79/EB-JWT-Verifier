import time
from unittest.mock import patch

import jwt
import pytest
from fastapi import Request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.dependencies.jwt.jwt_verifier import verify_jwt


@pytest.fixture(scope='module')
def _prepare_valid_rsa_key() -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_format_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_format_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_format_private_key, pem_format_public_key


def _prepare_fake_fast_apI_request_object(token) -> Request:
    bearer_token = f'Bearer {token}'
    return Request({
        'type': 'http',
        'headers': [(b'authorization', bearer_token.encode())],
    })


def test_jwt_verifier_succeeds(_prepare_valid_rsa_key):
    private_pem, public_pem = _prepare_valid_rsa_key
    now = int(time.time())

    payload = {
        'iat': now - 10,
        'exp': now + 10,
    }
    header = {
        'alg': 'RS256',
        'typ': 'JWT',
        # 'x5u': 'https://example.com/certs.pem'
    }

    token = jwt.encode(
        payload,
        private_pem,
        algorithm='RS256',
        headers=header,
    )

    fake_request = _prepare_fake_fast_apI_request_object(token=token)

    with patch(
            'app.dependencies.jwt.jwt_verifier.get_public_key_from_url',
            return_value=public_pem.decode(),
    ) as mock_fetch:
        verify_jwt(request=fake_request)
    mock_fetch.assert_called_once()

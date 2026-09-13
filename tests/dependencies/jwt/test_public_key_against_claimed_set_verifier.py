import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.dependencies.jwt.jwt_exceptions import NotSupportedJWTAlgorithmError, InvalidJWTSignatureError
from app.dependencies.jwt.public_key_against_claimed_set_verifier import verify_claimed_set_against_public_key


def test_wrong_token_and_wrong_key_public_key_raises_exception():
    with pytest.raises(InvalidJWTSignatureError):
        fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        fake_key_two = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = jwt.encode({'user': 'ata'}, fake_key_two, algorithm='RS256')

        verify_claimed_set_against_public_key(token, fake_key.public_key())


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
def test_wrong_public_key_algorithm_raises_exception():
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({'user': 'ata'}, "fake secret", algorithm='HS256')

    with pytest.raises(NotSupportedJWTAlgorithmError):
        verify_claimed_set_against_public_key(token, fake_key.public_key())


def test_correct_token_and_correct_key_public_key_does_not_raise_exception():
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({'user': 'ata'}, fake_key, algorithm='RS256')

    verify_claimed_set_against_public_key(token, fake_key.public_key())

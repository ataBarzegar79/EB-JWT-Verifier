from urllib.parse import urlparse, ParseResult
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes

from app.config import settings
from app.dependencies.jwt.exceptions.jwt_exceptions import (
    X5UNonStringError, X5UUrlUnreachableError, X5UUrlErroredResponseError,
    Invalid509EncodedCertificateError, X5uURLNotEligibleError,
)

x5u_allowed_hosts = settings.allowed_hosts

if settings.app_environment == 'TESTING' and (cert := settings.test_certificate_url):
    x5u_allowed_hosts.append(cert)


def veify_x5u_safety_and_get_from_url(x5u: str):
    parsed_url = _check_x5u_validity_and_safety(x5u=x5u)
    public_key = _get_public_key_from_url(url=parsed_url)
    return public_key


def _check_x5u_validity_and_safety(x5u) -> ParseResult:
    if not isinstance(x5u, str):
        raise X5UNonStringError()
    if x5u not in x5u_allowed_hosts:
        raise X5uURLNotEligibleError()
    return urlparse(x5u)


def _get_public_key_from_url(url: ParseResult) -> CertificatePublicKeyTypes:
    try:
        if url.scheme == 'file':
            raw_content = Path.from_uri(url.geturl()).read_bytes()
        else:
            with requests.get(url=url.geturl(), allow_redirects=False, timeout=(2, 4), stream=True) as response:
                response.raise_for_status()
                if response.is_redirect:
                    raise X5uURLNotEligibleError()
                raw_content = response.raw.read(decode_content=True)

        public_key = x509.load_pem_x509_certificate(raw_content).public_key()
    except requests.HTTPError:
        raise X5UUrlErroredResponseError()
    except (requests.ConnectionError, requests.Timeout, FileNotFoundError, OSError):
        raise X5UUrlUnreachableError()
    except ValueError:
        raise Invalid509EncodedCertificateError()
    return public_key

from urllib.parse import ParseResult
import requests
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography import x509

from app.dependencies.jwt.jwt_exceptions import X5UUrlUnreachableError, X5UUrlErroredResponseError, \
    Invalid509EncodedCertificateError


def get_public_key_from_url(url: ParseResult) -> CertificatePublicKeyTypes:
    try:
        maximum_bytes_allowed = 100000
        # todo: add to settings
        # redirects are not allowed
        with requests.get(url=url.geturl(), allow_redirects=False, timeout=(2, 4), stream=True) as response:
            response.raise_for_status()
            raw_content = response.raw.read(maximum_bytes_allowed)
        public_key = x509.load_pem_x509_certificate(raw_content).public_key()
    except (requests.ConnectionError, requests.Timeout):
        raise X5UUrlUnreachableError()
    except requests.HTTPError:
        raise X5UUrlErroredResponseError()
    except ValueError:
        raise Invalid509EncodedCertificateError()
    return public_key

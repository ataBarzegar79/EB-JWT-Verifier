from urllib.parse import urlparse, ParseResult

import requests
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography import x509

from app.dependencies.jwt.exceptions.jwt_exceptions import X5UNonStringError, X5UUrlUnreachableError, \
    X5UUrlErroredResponseError, \
    Invalid509EncodedCertificateError, X5uURLNotEligibleError

x5u_allowed_hosts = ["https://www.digicert.com/CACerts/DigiCertGlobalRootCA.crt.pem"]


# todo: add to settings
# todo: add test env url

def veify_x5u_safety_and_get_from_url(x5u: str):
    """
    At this stage:
    1. The x5u url is first checked, only whitelisted urls are allowed. This is to prevent malicious attacks.
    2. The url is then tried to be downloaded. The redirect is not allowed for security reasons.
    """
    parsed_url = _check_x5u_validity_and_safety(x5u=x5u_allowed_hosts[0])
    public_key = _get_public_key_from_url(url=parsed_url)
    return public_key


def _check_x5u_validity_and_safety(x5u) -> ParseResult:
    if not isinstance(x5u, str):
        raise X5UNonStringError()
    if x5u not in x5u_allowed_hosts:
        raise X5uURLNotEligibleError()
    parsed_url = urlparse(x5u)
    return parsed_url


def _get_public_key_from_url(url: ParseResult) -> CertificatePublicKeyTypes:
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

from urllib.parse import ParseResult
import requests
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from fastapi import HTTPException
from cryptography import x509


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
        raise HTTPException(status_code=503, detail="x5u url is timed out or unreachable.")
    except requests.HTTPError:
        raise HTTPException(status_code=502, detail="Specified x5u url responded with an error.")
    except ValueError:
        raise HTTPException(status_code=502, detail="Specified x5u file is not a valid x509 PEM encoded data.")
    return public_key

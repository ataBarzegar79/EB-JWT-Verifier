from urllib.parse import urlparse, ParseResult

from fastapi import HTTPException

x5u_allowed_hosts = ["https://www.digicert.com/CACerts/DigiCertGlobalRootCA.crt.pem"]
# todo: add to settings
# todo: add test env url


def _fail_if_protocol_is_not_https(parsed_url):
    if parsed_url.scheme.lower() != 'https':
        raise HTTPException(status_code=400, detail="x5u does not support HTTPS protocol.")


def _fail_if_port_is_not_443(parsed_url):
    if parsed_url.port is not None:
        if parsed_url.port != 443:
            raise HTTPException(status_code=400, detail="x5u does not support non-443 port and not a trusted url.")


def check_x5u_validity_and_safety(x5u) -> ParseResult:
    if not isinstance(x5u, str):
        raise HTTPException(status_code=400, detail="x5u is not string.")
    parsed_url = urlparse(x5u)
    if parsed_url not in x5u_allowed_hosts:
        _fail_if_protocol_is_not_https(parsed_url=parsed_url)
        _fail_if_port_is_not_443(parsed_url=parsed_url)
    return parsed_url


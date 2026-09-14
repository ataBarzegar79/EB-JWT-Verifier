import base64
import json
import time


class JWTFactoryException(Exception):
    pass


class FakeJwtFactory:
    """
    This file is a fake data generator for jwt.

    """

    def __init__(self):
        self.default_headers = {
            "alg": "RS256",
            "typ": "JWT"
        }
        self.default_payload = {
            "iss": "https://example.com",
            "iat": int(time.time()) - 120,
            "exp": int(time.time()) + 120,
            "x5u": "https://example.com/user"
        }
        self.fake_signature = "KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

    def update_header(self, key, value):
        if key not in self.default_headers:
            raise JWTFactoryException("Invalid header key")
        try:
            self.default_headers[key] = value
        except Exception as e:
            raise JWTFactoryException(e)
        return self

    def update_headers(self, headers):
        self.default_headers = headers
        return self

    def add_header(self, key, value):
        if key not in self.default_headers:
            self.default_headers[key] = value
            return self
        raise JWTFactoryException("Header already exists")

    def update_payload(self, key, value):
        if key not in self.default_payload:
            raise JWTFactoryException("Invalid payload key")
        try:
            self.default_payload[key] = value
            return self
        except Exception as e:
            raise JWTFactoryException(e)

    def update_payloads(self, payloads):
        self.default_payload = payloads
        return self

    def add_payload(self, key, value):
        if key not in self.default_payload:
            self.default_payload[key] = value
        raise JWTFactoryException("Payload already exists")

    def _encode_to_base64_url(self, data):
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def makeBearer(self):
        return "Bearer " + self.make()

    def make(self):
        header_base64_url = self._encode_to_base64_url(self.default_headers)
        payload_base64_url = self._encode_to_base64_url(self.default_payload)
        return f"{header_base64_url}.{payload_base64_url}.{self.fake_signature}"

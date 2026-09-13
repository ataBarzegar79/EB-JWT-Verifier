from fastapi import Request

from app.dependencies.jwt.public_key_against_claimed_set_verifier import verify_claimed_set_against_public_key
from app.dependencies.jwt.x5u_url_fetcher import get_public_key_from_url
from app.dependencies.jwt.x5u_verifier import check_x5u_validity_and_safety
from app.dependencies.jwt.jwt_header_and_payload_verifier import check_header_and_payload
from app.dependencies.jwt.authorization_header_structure_verifier import check_authorization_header_structure


def verify_jwt(request: Request) -> None:
    auth_header = request.headers.get("Authorization")
    jwt_token = check_authorization_header_structure(auth_header=auth_header)
    decoded_tokens = check_header_and_payload(jwt_token=jwt_token)
    parsed_url = check_x5u_validity_and_safety(x5u=decoded_tokens['header']['x5u'])
    public_key = get_public_key_from_url(url=parsed_url)
    verify_claimed_set_against_public_key(token=jwt_token, public_key=public_key)
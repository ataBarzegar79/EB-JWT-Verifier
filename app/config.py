import os

from pydantic_settings import BaseSettings


# should be considered read-only.
class Settings(BaseSettings):
    app_environment: str | None = os.getenv('ENVIRONMENT')
    x5u_test_url: str | None = os.getenv('X5U_TESTING_CERT')
    allowed_algorithm: str = 'RS256'
    allowed_type: str = 'JWT'
    allowed_hosts: list[str] = []  # new hosts can be addded here.


settings = Settings()

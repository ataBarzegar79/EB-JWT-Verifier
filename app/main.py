import logging
from pathlib import Path

from fastapi import FastAPI, Depends

from app.dependencies.jwt.verifier import verify_jwt

LOG_DIR = Path(__file__).parent
logging.basicConfig(
    filename=LOG_DIR / 'logs' / 'app.log',
    filemode='a',
    level=logging.ERROR
)

app = FastAPI()


@app.get("/auth", dependencies=[Depends(verify_jwt)])
def authenticate():
    """
    This is the happy path.
    The main jwt logic is done in the dependency. This way it can also be added to new apis in future.

    """
    return {"valid": "true"}

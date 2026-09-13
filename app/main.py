from fastapi import FastAPI, Depends

from app.dependencies.jwt.verifier import verify_jwt

app = FastAPI()


@app.get("/auth", dependencies=[Depends(verify_jwt)])
def authenticate():
    """
    This is the happy path.
    The main jwt logic is done in the dependency. This way it can also be added to new apis in future.

    """
    return {"valid": "true"}

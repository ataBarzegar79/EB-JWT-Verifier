from fastapi import FastAPI, Depends

from app.dependencies.jwt.verifier import verify_jwt

app = FastAPI()


@app.get("/auth", dependencies=[Depends(verify_jwt)])
def authenticate():
    return {"valid": "true"}

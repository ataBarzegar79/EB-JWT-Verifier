# EB JWT Verifier

Verify JWT tokens with JWTVerifier.

## Setup

## Setup

```bash
cp .env.example .env
mkdir -p app/logs
touch app/logs/app.log
```


## Run

### With Docker (Compose) - RECOMMENDED
This file is for development purposes only.
```bash
docker compose up --build
```

**Without Docker** (you should install [uv](https://docs.astral.sh/uv/))

```bash
uv sync
uv run --env-file .env fastapi dev app/main.py --port 8080
```

API: GET `http://localhost:8080/auth` · 

and put a valid JWT token with a valid X5U header. 

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/auth
```

### Maunal Testing
System only downloads certificates from its whitelist, so the url should explisitly be mentioned by the system itself. Otherwise, there would be 
401 error. You can add valid urls to the config.py

For manual test, as mentioned above, keep your .env accessible to the project. 
    There is a valid pair of keys on the project that you can use for test. But it only works if environment variables are set. 
    'ENVIROMENT' should be set to 'TESTING' and 'X5U_TESTING_CERT' should show the path to the certificate in your machine.
#### X5U_TESTING_CERT Value
X5U_TESTING_CERT value can be different based on your machine. 
For Docker, put it inside the fake files directory (as already is, they can be also used) in the tests in the project as mentioned in the .env.example file. 
    For other machines, search how files can be put as the url form in the env. 

The other private key in the project (or your own file) can be used to sign the JWT token. Use [JWT IO](https://jwt.io)
's JWT encoder section to generate a JWT token. 
Or you can generate with your very own script:) 

For the x5u header in the JWT, put the url of the certificate in the whitelist or for testing, what exactly mentioned in the env file. 
Then, everything should be fine, call the API with the JWT token. Add it to the Authorization header with the Bearer prefix.

### Example
```aiignore
curl -H "Authorization: Bearer <token>" http://localhost:8080/auth
```

## Running Tests

**With Docker**

```bash
docker compose exec api pytest
```

**Without Docker**

```bash
uv run pytest
```


## Return Samples: 

### sucessful One: 
```aiignore
HTTP/1.1 200 OK
date: Sun, 13 Sep 2026 22:27:15 GMT
server: uvicorn
content-length: 16
content-type: application/json

{"valid":"true"}
```
### unsucessful response: 
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:28:51 GMT
server: uvicorn
content-length: 53
content-type: application/json

{"detail":"Required claim is missing: exp, iat, x5u"}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:30:18 GMT
server: uvicorn
content-length: 65
content-type: application/json

{"detail":"The specified x5u Url is not verified in the system."}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:31:33 GMT
server: uvicorn
content-length: 46
content-type: application/json

{"detail":"Token algorithm is not supported."}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:32:28 GMT
server: uvicorn
content-length: 41
content-type: application/json

{"detail":"Token type is not supported."}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:33:33 GMT
server: uvicorn
content-length: 65
content-type: application/json

{"detail":"The specified x5u Url is not verified in the system."}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:38:00 GMT
server: uvicorn
content-length: 30
content-type: application/json

{"detail":"iat is in future."}
```
```aiignore
HTTP/1.1 401 Unauthorized
date: Sun, 13 Sep 2026 22:38:31 GMT
server: uvicorn
content-length: 29
content-type: application/json

{"detail":"exp has expired."}


```
```aiignore
HTTP/1.1 500 Internal Server Error
date: Mon, 14 Sep 2026 20:35:30 GMT
server: uvicorn
content-length: 48
content-type: application/json

{"detail":"Unhandled error while verifying JWT"}
```

and so on. You can find more samples in the exceptions directory.
## Architecture

The project comes with a single API. But what it tries to solve is verifying JWT tokens, which might be mandatory to more than one endpoint.
So, the jwt vefication is done through a middleware-like approach. Middlewares in FastAPI are called for all endpoints, and specifying endpoints is not possible.
Therefore, the verification is done through a decorator and depenerdency. With this in hand, new APIs can also benefit from the verification.

### Pipeline Explanation
1. First, general cheks are done, such as the presence of the JWT token, and structure of the JWT. The JWT claimedset is also checked for reuiqred parmeters (e.g. iss, exp).
2. The X5U header is checked, it is not trusted unless it is in the whitelist. Also, redirec from a url also fails. 
3. Finally, the JWT is verified against the trusted certificates.

### Security Considerations
The most important part of the project is the verification of the JWT through the provided x5u header. It is important, for instance, an attacker can generate its own public and private keys, and use them to sign a JWT token by 
putting the public key url in the x5u header. Among different resources, I concluded to solve this problem by using the whitelist and also disallowing redirections.
Also, alogrithm type is forced by the system, not the user. The whitelist approach also avoids sending request to our own ip ranges. 

### Error Handling
Error handling plays a crucial role in the project. The project heavily relies on the fastapi exception handling. 
With one difference, the project also creates a custom exception on top of the fastapi exception by inheritence, which makes them to use easily in the code and tests. 
They can be checked inside the exceptions' directory.



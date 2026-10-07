"""Recipe: TOKEN-INTEGRITY + TOKEN-CLAIMS + AUTHN-ENDPOINT for FastAPI with PyJWT.

Tested against: fastapi >=0.110,<1.0 · pyjwt >=2.8,<3.0
Key material comes from the environment; never hardcode it.
"""
import os
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_KEY = os.environ["JWT_KEY"]              # fail fast if missing
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
ALGORITHMS = ["HS256"]                        # pinned; never derived from the token header

bearer = HTTPBearer(auto_error=False)


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> dict:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if creds is None:
        raise unauthorized
    try:
        claims = jwt.decode(
            creds.credentials,
            JWT_KEY,
            algorithms=ALGORITHMS,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "aud", "sub"]},
        )
    except jwt.InvalidTokenError:
        raise unauthorized                    # one generic error; no detail leakage
    return {"id": claims["sub"]}

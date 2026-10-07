from typing import Annotated

from fastapi import Depends, Security
from fastapi.security import OAuth2PasswordBearer

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")


def get_db():
    yield {}


def get_current_user(token: Annotated[str, Depends(oauth2)]):
    return {"id": 1, "token": token}


def require_admin(user: Annotated[dict, Depends(get_current_user)]):
    return user


def get_scoped_user(token: Annotated[str, Security(oauth2, scopes=["reports"])]):
    return {"id": 1}


DB = Annotated[dict, Depends(get_db)]
User = Annotated[dict, Depends(get_current_user)]

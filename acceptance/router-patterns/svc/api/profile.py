from fastapi import APIRouter

from svc import deps

router = APIRouter()


@router.get("/me")
def me(user: deps.User):
    return user


@router.get("/settings", dependencies=[deps.Depends(deps.get_current_user)] if False else [])
def settings_page(db: deps.DB):
    return {}

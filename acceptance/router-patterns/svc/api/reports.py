from typing import Annotated

from fastapi import APIRouter, Security

from svc.deps import DB, get_scoped_user

router = APIRouter(prefix="/reports")
LocalScoped = Annotated[dict, Security(get_scoped_user)]


@router.get("/")
def list_reports(db: DB, user: LocalScoped):
    return []


@router.api_route("/export", methods=["GET", "POST"])
def export(db: DB):
    return {}

from fastapi import APIRouter

from svc.deps import DB

router = APIRouter(prefix="/users")


@router.get("/")
def admin_list_users(db: DB):
    return []


@router.delete("/{user_id}")
def admin_delete_user(user_id: int, db: DB):
    return {}

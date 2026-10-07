from fastapi import APIRouter

router = APIRouter(prefix="/debug")


@router.post("/reset")
def reset():
    return {}

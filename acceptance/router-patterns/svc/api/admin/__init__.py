from fastapi import APIRouter, Depends

from svc.deps import require_admin

from .users import router as users_router

router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])
router.include_router(users_router)

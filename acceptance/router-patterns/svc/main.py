import os
from typing import Annotated

from fastapi import Depends, FastAPI

from svc.api import dynamic, profile, reports
from svc.api.admin import router as admin_router
from svc.deps import get_current_user

API = "/api"
app = FastAPI()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/whoami")
def whoami(user: Annotated[dict, Depends(get_current_user)]):
    return user


app.include_router(reports.router, prefix=API)
app.include_router(admin_router, prefix=API)
app.include_router(profile.router, prefix=API + "/profile", dependencies=[Depends(get_current_user)])
app.include_router(dynamic.router, prefix=os.environ.get("PLUGIN_PREFIX", "/ext"))
if os.environ.get("ENABLE_DEBUG") == "1":
    from svc.api import debug

    app.include_router(debug.router)

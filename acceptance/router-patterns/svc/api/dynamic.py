from fastapi import APIRouter

router = APIRouter()

for name in ("alpha", "beta"):
    def handler(name=name):
        return {"name": name}

    router.add_api_route(f"/plugins/{name}", handler, methods=["GET"])


orphan = APIRouter()


@orphan.get("/never-mounted")
def never_mounted():
    return {}

from typing import Annotated

from auth import get_current_user
from fastapi import Depends, FastAPI

app = FastAPI()


@app.get("/documents/{doc_id}")
def read_document(doc_id: int, user: Annotated[dict, Depends(get_current_user)]):
    return {"id": doc_id, "owner": user["id"]}


@app.get("/exports")
def exports():
    return {"export": []}

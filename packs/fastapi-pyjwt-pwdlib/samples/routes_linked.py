# Fixture only: three alternative wirings of the same route, one per supported form.
from typing import Annotated
from fastapi import Depends, FastAPI

app = FastAPI()

def get_current_user(): ...

@app.get("/documents/{doc_id}")
async def read_document_annotated(doc_id: int, user: Annotated[dict, Depends(get_current_user)]):
    return {"id": doc_id}

@app.get("/documents/{doc_id}")
def read_document_default(doc_id: int, user=Depends(get_current_user)):
    return {"id": doc_id}

@app.get("/documents/{doc_id}", dependencies=[Depends(get_current_user)])
async def read_document_decorator(doc_id: int):
    return {"id": doc_id}

# Fixture only: near-misses that must NOT count as GET /documents/{doc_id} -> get_current_user.
from fastapi import Depends, FastAPI

app = FastAPI()

def get_current_user(): ...
def get_db(): ...

@app.get("/documents/{doc_id}")              # right route, wrong dependency
async def read_document(doc_id: int, db=Depends(get_db)):
    return {"id": doc_id}

@app.post("/documents/{doc_id}")             # right path and dependency, wrong method
async def update_document(doc_id: int, user=Depends(get_current_user)):
    return {"id": doc_id}

@app.get("/profile")                         # right method and dependency, wrong path
def profile(user=Depends(get_current_user)):
    return user

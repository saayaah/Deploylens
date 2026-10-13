from fastapi import FastAPI

from app.config import settings

app = FastAPI(title="Demo Notes API")


@app.get("/notes")
def list_notes() -> list[dict]:
    return [{"id": 1, "text": "hello"}]

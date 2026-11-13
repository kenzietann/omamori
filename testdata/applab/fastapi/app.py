# A small FastAPI app on uvicorn, with the default logging of uvicorn.
import logging

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()
logger = logging.getLogger("uvicorn.error")


@app.post("/auth/login")
async def login(request: Request):
    body = await request.json()
    if body.get("username") == "alice" and body.get("password") == "Summer2026!":
        return {"token": "t"}
    logger.warning("Failed login for %s from %s", body.get("username"), request.client.host)
    raise HTTPException(status_code=401, detail="invalid credentials")


@app.get("/api/items")
async def items(id: str = ""):
    if "'" in id:
        logger.error('asyncpg.exceptions.PostgresSyntaxError: syntax error at or near "%s"', id)
        raise HTTPException(status_code=500, detail="server error")
    return []

"""lists.py — Whitelist / blacklist management."""

from fastapi import APIRouter, Request

router = APIRouter()

def _db():
    from db import db_manager
    return db_manager

@router.post("/whitelist/add")
async def wl_add(request: Request):
    d = await request.json()
    _db().add_whitelist(d.get("ip","").strip(), d.get("note",""))
    return {"status": "added"}

@router.post("/whitelist/remove")
async def wl_remove(request: Request):
    d = await request.json()
    _db().remove_whitelist(d.get("ip","").strip())
    return {"status": "removed"}

@router.post("/blacklist/add")
async def bl_add(request: Request):
    d = await request.json()
    _db().add_blacklist(d.get("ip","").strip(), d.get("reason",""))
    return {"status": "added"}

@router.post("/blacklist/remove")
async def bl_remove(request: Request):
    d = await request.json()
    _db().remove_blacklist(d.get("ip","").strip())
    return {"status": "removed"}

@router.get("/whitelist")
def get_wl():
    return _db().get_whitelist()

@router.get("/blacklist")
def get_bl():
    return _db().get_blacklist()

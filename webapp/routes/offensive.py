"""offensive.py — Offensive module controls."""

from fastapi import APIRouter, Request

router = APIRouter()

@router.post("/discovery/start")
async def disc_start(request: Request):
    d = await request.json()
    from offensive import discovery
    return discovery.start(d.get("interface","eth0"), subnet=d.get("subnet") or None)

@router.post("/discovery/stop")
async def disc_stop():
    from offensive import discovery
    discovery.stop()
    return {"status": "stopped"}

@router.post("/recon")
async def recon(request: Request):
    d = await request.json()
    from offensive import recon as r
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, r.run, d.get("target_ip"))
    return result

@router.post("/attack_sim")
async def attack_sim(request: Request):
    d = await request.json()
    from offensive import attack_sim as sim
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None, sim.run, d.get("target_ip"), d.get("attack_type","all"), d.get("interface","eth0"))
    return result

@router.post("/arp/start")
async def arp_start(request: Request):
    d = await request.json()
    from offensive import arp_engine
    arp_engine.start(d["target_ip"], d["gateway_ip"],
                     d.get("interface","eth0"), d.get("mode","two_way"))
    return {"status": "started"}

@router.post("/arp/stop")
async def arp_stop():
    from offensive import arp_engine
    arp_engine.stop()
    return {"status": "stopped"}

@router.post("/dns_spoof/start")
async def dns_start(request: Request):
    d = await request.json()
    from offensive import dns_spoof
    dns_spoof.start(d.get("target_ip"), d["domain"], d["spoof_ip"], d.get("interface","eth0"))
    return {"status": "started"}

@router.post("/dns_spoof/stop")
async def dns_stop():
    from offensive import dns_spoof
    dns_spoof.stop()
    return {"status": "stopped"}

@router.post("/ssl_strip/start")
async def ssl_start(request: Request):
    d = await request.json()
    from offensive import ssl_strip
    ssl_strip.start(d.get("interface","eth0"), d.get("target_ip"))
    return {"status": "started"}

@router.post("/ssl_strip/stop")
async def ssl_stop():
    from offensive import ssl_strip
    ssl_strip.stop()
    return {"status": "stopped"}

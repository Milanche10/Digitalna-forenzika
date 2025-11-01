# server.py
import asyncio
import json
import uuid
from typing import Dict, Any, Set, Optional
from datetime import datetime, timezone

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="SecureTalk Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_headers=["*"],
    allow_methods=["*"],
)

USERS: Dict[str, Dict[str, Any]] = {}
ROOMS: Dict[str, Set[str]] = {}

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

async def send_json(ws: WebSocket, payload: dict):
    try:
        await ws.send_text(json.dumps(payload, ensure_ascii=False))
    except Exception:
        raise

async def notify_room(room: str, payload: dict, exclude_user_id: Optional[str] = None):
    if not room:
        return
    members = list(ROOMS.get(room, set()))
    for uid in members:
        if exclude_user_id and uid == exclude_user_id:
            continue
        uinfo = USERS.get(uid)
        if not uinfo:
            continue
        try:
            await send_json(uinfo["ws"], payload)
        except Exception:
            pass

def join_room(user_id: str, room: str):
    if room not in ROOMS:
        ROOMS[room] = set()
    ROOMS[room].add(user_id)
    USERS[user_id]["room"] = room

def leave_room(user_id: str):
    room = USERS[user_id].get("room")
    if room and room in ROOMS:
        ROOMS[room].discard(user_id)
        if not ROOMS[room]:
            del ROOMS[room]
    USERS[user_id]["room"] = None

def room_roster(room: str):
    members = []
    for uid in ROOMS.get(room, set()):
        u = USERS.get(uid)
        if not u:
            continue
        members.append({
            "user_id": uid,
            "username": u.get("username"),
            "pub_dh": u.get("pub_dh"),
            "pub_sign": u.get("pub_sign"),
        })
    return members

def find_user_by_username(username: str) -> Optional[str]:
    for uid, info in USERS.items():
        if info.get("username") == username:
            return uid
    return None

@app.get("/")
async def index():
    return {"status": "ok", "time": now_iso()}

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    user_id = str(uuid.uuid4())
    USERS[user_id] = {
        "username": None,
        "ws": ws,
        "room": None,
        "pub_dh": None,
        "pub_sign": None,
        "joined_at": now_iso(),
    }
    print(f"[SERVER] New websocket connection: user_id={user_id}")
    try:
        await send_json(ws, {"type": "hello", "user_id": user_id, "server_time": now_iso()})
        while True:
            text = await ws.receive_text()
            data = json.loads(text)
            mtype = data.get("type")

            if mtype == "register":
                USERS[user_id]["username"] = data.get("username")
                USERS[user_id]["pub_dh"] = data.get("pub_dh")
                USERS[user_id]["pub_sign"] = data.get("pub_sign")
                print(f"[SERVER] REGISTER user_id={user_id} username={USERS[user_id]['username']}")
                await send_json(ws, {"type": "register_ok", "user_id": user_id})

            elif mtype == "join_room":
                room = data.get("room") or "lobby"
                prev = USERS[user_id].get("room")
                if prev and prev != room:
                    leave_room(user_id)
                join_room(user_id, room)
                print(f"[SERVER] {USERS[user_id]['username']} joined room '{room}'")
                await send_json(ws, {"type": "room_joined", "room": room, "members": room_roster(room)})
                await notify_room(room, {
                    "type": "presence",
                    "event": "join",
                    "user": {
                        "user_id": user_id,
                        "username": USERS[user_id]["username"],
                        "pub_dh": USERS[user_id]["pub_dh"],
                        "pub_sign": USERS[user_id]["pub_sign"],
                    }
                }, exclude_user_id=user_id)

            elif mtype == "leave_room":
                old = USERS[user_id].get("room")
                leave_room(user_id)
                if old:
                    await notify_room(old, {
                        "type": "presence",
                        "event": "leave",
                        "user": {"user_id": user_id, "username": USERS[user_id]["username"]}
                    }, exclude_user_id=user_id)
                await send_json(ws, {"type": "left_ok"})

            elif mtype == "message":
                cipher_dict = data.get("cipher_dict") or {}
                if data.get("to") and data.get("cipher"):
                    cipher_dict = {data.get("to"): data.get("cipher")}
                for peer_id, cipher in cipher_dict.items():
                    uinfo = USERS.get(peer_id)
                    if uinfo:
                        payload = {
                            "type": "message",
                            "from": user_id,
                            "cipher": cipher,
                            "msg_id": data.get("msg_id"),
                            "ttl_ms": data.get("ttl_ms"),
                            "ts": now_iso(),
                        }
                        try:
                            await send_json(uinfo["ws"], payload)
                        except Exception:
                            pass
                print(f"[SERVER] Forwarded message from {USERS[user_id].get('username')} -> targets({len(cipher_dict)})")

            elif mtype == "file":
                cipher_dict = data.get("cipher_dict") or {}
                if data.get("to") and (data.get("cipher_meta") or data.get("cipher_chunks")):
                    cdata = {k: data[k] for k in data.keys() if k not in ("type", "to")}
                    cipher_dict = {data.get("to"): cdata}
                for peer_id, cdata in cipher_dict.items():
                    uinfo = USERS.get(peer_id)
                    if uinfo:
                        payload = {"type": "file", "from": user_id}
                        for k, v in cdata.items():
                            payload[k] = v
                        payload["ts"] = now_iso()
                        try:
                            await send_json(uinfo["ws"], payload)
                            # print minimal info for debug
                            msg_id = payload.get("msg_id", "<no-msg-id>")
                            chunk_index = payload.get("chunk_index", 0)
                            chunk_total = payload.get("chunk_total", '?')
                            print(f"[SERVER] Forwarded file chunk from {USERS[user_id].get('username')} -> {USERS.get(peer_id, {}).get('username')} msg_id={msg_id} chunk={chunk_index}/{chunk_total}")
                        except Exception:
                            pass

            elif mtype in ("call_invite", "call_answer", "call_end", "call_ice"):
                to_field = data.get("to")
                target_uid = None
                target_info = None
                if to_field in USERS:
                    target_uid = to_field
                    target_info = USERS.get(target_uid)
                else:
                    lookup = find_user_by_username(to_field)
                    if lookup:
                        target_uid = lookup
                        target_info = USERS.get(lookup)
                if target_info:
                    fwd = dict(data)
                    fwd["from"] = user_id
                    fwd["to"] = target_uid
                    try:
                        await send_json(target_info["ws"], fwd)
                    except Exception:
                        pass

            elif mtype == "room_members":
                room = USERS[user_id].get("room") or "lobby"
                await send_json(ws, {"type": "room_members", "room": room, "members": room_roster(room)})

            else:
                await send_json(ws, {"type": "error", "message": f"Unknown type: {mtype}"})
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[SERVER] Connection error: {e}")
    finally:
        u = USERS.get(user_id)
        if u:
            room = u.get("room")
            username = u.get("username")
            if room:
                await notify_room(room, {"type": "presence", "event": "leave", "user": {"user_id": user_id, "username": username}}, exclude_user_id=user_id)
            USERS.pop(user_id, None)
            print(f"[SERVER] Disconnected user_id={user_id} username={username}")

def run_server(port: int = 8765):
    print(f"[SERVER] Starting uvicorn on 0.0.0.0:{port}")
    uvicorn.run("server:app", host="0.0.0.0", port=port, log_level="info")

if __name__ == "__main__":
    run_server(8765)

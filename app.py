"""
PrivAI Backend Server (Open Source Edition)
-------------------------------------------
Acts as the secure gatekeeper between the Client, Firebase, and the Worker Node.

Security Features:
- End-to-End Encryption for Database Storage (Fernet/AES).
- JWT Authentication.
- Rate Limiting.
- Role-Based Access Control (Admin/User).

Environment Variables Required:
- JWT_SECRET_KEY
- WORKER_SECRET_KEY
- FIREBASE_SERVICE_ACCOUNT_BASE64
- DATABASE_ENCRYPTION_KEY (New!)
"""

import asyncio
import json
import base64
import datetime
import os
import bcrypt
import jwt
import secrets
import uuid
from typing import List, Optional, Dict, Union
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body, Depends, Header
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import uvicorn
import firebase_admin
from firebase_admin import credentials, firestore
from cryptography.fernet import Fernet

# ---------------- CONFIGURATION ----------------

# Retrieve Keys
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
WORKER_SECRET_KEY = os.environ.get("WORKER_SECRET_KEY")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
DB_ENCRYPTION_KEY = os.environ.get("DATABASE_ENCRYPTION_KEY")

SSL_CERTFILE = "cert.pem" if os.path.exists("cert.pem") else None
SSL_KEYFILE = "key.pem" if os.path.exists("key.pem") else None

# Check Critical Keys
if not JWT_SECRET_KEY:
    print("WARNING: JWT_SECRET_KEY not found. Using insecure default for dev.")
    JWT_SECRET_KEY = "dev_insecure_key_do_not_use_in_prod"

# Setup Encryption Cipher
cipher_suite = None
if DB_ENCRYPTION_KEY:
    try:
        cipher_suite = Fernet(DB_ENCRYPTION_KEY.encode())
    except Exception as e:
        print(f"CRITICAL: Invalid DATABASE_ENCRYPTION_KEY. {e}")
        exit(1)
else:
    # Generate a key for the user to help them setup
    generated_key = Fernet.generate_key().decode()
    print("\n" + "="*60)
    print("CRITICAL: DATABASE_ENCRYPTION_KEY IS MISSING.")
    print("Data stored in Firebase will NOT be encrypted.")
    print(f"Please add this to your environment variables:\nDATABASE_ENCRYPTION_KEY={generated_key}")
    print("="*60 + "\n")
    # We allow running without it for testing, but it's not "Private"
    cipher_suite = None

# ---------------- FIREBASE INIT ----------------
try:
    encoded_key = os.environ.get("FIREBASE_SERVICE_ACCOUNT_BASE64")
    if not encoded_key: raise ValueError("FIREBASE_SERVICE_ACCOUNT_BASE64 missing")
    decoded_key = base64.b64decode(encoded_key).decode("utf-8")
    cred = credentials.Certificate(json.loads(decoded_key))
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    users_collection = db.collection("users")
    chats_collection = db.collection("chats")
    settings_collection = db.collection("settings")
    print("Firebase initialized successfully.")
except Exception as e:
    print(f"Firebase init failed: {e}")
    exit(1)

# ---------------- MODELS ----------------
class ApiChatRequest(BaseModel):
    message: str
    history: List[dict] = []

class ChatData(BaseModel):
    id: Optional[str] = None 
    name: str
    type: str
    timestamp: str
    history: List[dict]
    pdfName: Optional[str] = None
    docId: Optional[str] = None

# ---------------- GLOBALS ----------------
pending_api_responses: Dict[str, dict] = {}

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ---------------- ENCRYPTION HELPERS ----------------
def encrypt_data(data: Union[dict, list]) -> Union[str, list]:
    """Encrypts a JSON object to a string. Returns original if no key configured."""
    if not cipher_suite: return data
    try:
        json_str = json.dumps(data)
        return cipher_suite.encrypt(json_str.encode()).decode()
    except Exception as e:
        print(f"Encryption error: {e}")
        return data

def decrypt_data(token: Union[str, list, dict]) -> Union[dict, list]:
    """Decrypts a string back to JSON. Handles legacy plaintext gracefully."""
    if not cipher_suite: return token
    if not isinstance(token, str): return token # Already decrypted or legacy
    try:
        decrypted_str = cipher_suite.decrypt(token.encode()).decode()
        return json.loads(decrypted_str)
    except Exception:
        # Fallback: Data might be old plaintext from before encryption was enabled
        return token

# ---------------- RATE LIMITER ----------------
async def check_rate_limit(username: str, source: str = "web"):
    if username.startswith("guest_"): return True, ""
    user_ref = users_collection.document(username)
    doc = user_ref.get()
    if not doc.exists: return False, "User not found"

    data = doc.to_dict()
    user_ref.update({"usage_count": firestore.Increment(1)})

    if source == "web":
        user_ref.update({"web_usage_count": firestore.Increment(1)})
        return True, ""

    user_ref.update({"api_usage_count": firestore.Increment(1)})
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.strftime("%Y-%m-%d")

    last_reset = data.get("last_reset_date", "")
    daily_count = data.get("daily_prompts", 0)

    if last_reset != today:
        daily_count = 0
        last_reset = today

    if daily_count >= 100:
        return False, "API Daily limit reached (100/100)."

    history = data.get("request_history", [])
    one_minute_ago = now - datetime.timedelta(seconds=60)
    valid_history = [t for t in history if datetime.datetime.fromisoformat(t) > one_minute_ago]

    if len(valid_history) >= 10:
        return False, "API Rate limit: 10/min."

    valid_history.append(now.isoformat())
    user_ref.update({
        "daily_prompts": daily_count + 1,
        "last_reset_date": last_reset,
        "request_history": valid_history
    })
    return True, ""

# ---------------- DEEP THINK LIMITER ----------------
async def check_deep_think_limit(username: str):
    if username.startswith("guest_"):
        return False, "Deep Think is reserved for registered users. Please sign in."

    user_ref = users_collection.document(username)
    doc = user_ref.get()
    if not doc.exists: 
        return False, "User not found"

    data = doc.to_dict()
    now = datetime.datetime.now(datetime.timezone.utc)
    today = now.strftime("%Y-%m-%d")

    last_deep_reset = data.get("last_deep_reset", "")
    deep_count = data.get("daily_deep_count", 0)

    if last_deep_reset != today:
        deep_count = 0
        last_deep_reset = today

    if deep_count >= 3:
        return False, "Daily Deep Think limit reached (3/3). Try again tomorrow!"

    user_ref.update({
        "daily_deep_count": deep_count + 1,
        "last_deep_reset": last_deep_reset
    })
    return True, ""

# ---------------- CONNECTION MANAGER ----------------
class ConnectionManager:
    def __init__(self):
        self.web_clients = {}
        self.local_worker = None

    async def connect_web(self, ws: WebSocket, user: str):
        self.web_clients[user] = ws

    async def connect_worker(self, ws: WebSocket):
        self.local_worker = ws

    async def disconnect_worker(self):
        self.local_worker = None

    def disconnect_web(self, user: str):
        if user in self.web_clients: del self.web_clients[user]

    async def send_to_worker(self, msg: str):
        if self.local_worker: 
            await self.local_worker.send_text(msg)
        else:
            print("Attempted to send to worker, but worker is offline.")

    async def send_to_client(self, msg: str):
        try:
            data = json.loads(msg)
            user = data.get("user_id")
            
            # Handle External API Requests
            if user and user.startswith("api_req_") and user in pending_api_responses:
                state = pending_api_responses[user]
                if data["type"] == "stream_chunk": 
                    state["buffer"] += data.get("data", "")
                elif data["type"] in ["stream_end", "error"]:
                    if not state["future"].done():
                        state["future"].set_result(state["buffer"] if data["type"] != "error" else f"Error: {data.get('data')}")
                return
            
            # Handle Web Interface Clients
            if user and user in self.web_clients:
                await self.web_clients[user].send_text(msg)
        except Exception as e:
            print(f"Error sending to client: {e}")

manager = ConnectionManager()

# ---------------- AUTH & ADMIN ----------------
def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)})
    return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm="HS256")

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try: 
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload["sub"]
    except: 
        raise HTTPException(401, "Invalid session")

async def verify_admin(current_user: str = Depends(get_current_user)):
    if current_user != ADMIN_USERNAME: 
        raise HTTPException(403, "Admin only access")
    return current_user

# ---------------- ROUTES ----------------
@app.get("/")
async def index(): return FileResponse("index.html")

@app.get("/privacy")
async def privacy(): return FileResponse("privacy.html")

@app.post("/signup")
async def signup(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    if not u or not p: raise HTTPException(400, "Missing fields")
    if users_collection.document(u).get().exists: raise HTTPException(400, "User exists")
    users_collection.document(u).set({
        "username": u, "password": bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode(),
        "api_keys": {}, "usage_count": 0, "web_usage_count": 0, "api_usage_count": 0,
        "daily_prompts": 0, "daily_deep_count": 0, "last_deep_reset": "", 
        "request_history": [], "created_at": datetime.datetime.now().isoformat()
    })
    return {"ok": True}

@app.post("/auth/login")
async def login(data: dict = Body(...)):
    u, p = data.get("username"), data.get("password")
    doc = users_collection.document(u).get()
    if not doc.exists or not bcrypt.checkpw(p.encode(), doc.to_dict()["password"].encode()):
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": u, "is_admin": u == ADMIN_USERNAME})
    return {"access_token": token, "token_type": "bearer"}

# --- BANNER SYSTEM ---
@app.get("/banner")
async def get_banner():
    doc = settings_collection.document("global_banner").get()
    return doc.to_dict() if doc.exists else {"active": False}

@app.post("/admin/banner")
async def set_banner(data: dict = Body(...), admin: str = Depends(verify_admin)):
    settings_collection.document("global_banner").set(data)
    return {"ok": True}

# --- ADMIN STATS ---
@app.get("/admin/stats")
async def admin_stats(admin: str = Depends(verify_admin)):
    users = []
    for doc in users_collection.stream():
        d = doc.to_dict()
        users.append({
            "username": d.get("username"), 
            "usage": d.get("usage_count", 0), 
            "api_usage": d.get("api_usage_count", 0), 
            "keys": len(d.get("api_keys", {})), 
            "created": d.get("created_at")
        })
    return sorted(users, key=lambda x: x["usage"], reverse=True)

# --- KEY MANAGEMENT ---
@app.post("/keys")
async def gen_key(data: dict = Body(...), user: str = Depends(get_current_user)):
    doc = users_collection.document(user).get()
    if len(doc.to_dict().get("api_keys", {})) >= 1: raise HTTPException(400, "Limit: 1 Key")
    key = f"sk-{secrets.token_urlsafe(16)}"
    users_collection.document(user).update({f"api_keys.{key}": data.get("name","Key")})
    return {"key": key}

@app.get("/keys")
async def get_keys(user: str = Depends(get_current_user)):
    doc = users_collection.document(user).get()
    return [{"key":k, "name":v} for k,v in doc.to_dict().get("api_keys", {}).items()]

@app.delete("/keys/{key}")
async def del_key(key: str, user: str = Depends(get_current_user)):
    users_collection.document(user).update({f"api_keys.{key}": firestore.DELETE_FIELD})
    return {"ok": True}

# --- CHATS (ENCRYPTED) ---
@app.get("/chats")
async def get_chats(user: str = Depends(get_current_user)):
    # Decrypt chat names/previews on load if necessary, 
    # but for list performance, we usually only decrypt the specific chat on load.
    # However, to be safe, we return basic info. The full history is fetched in /chats/{cid}
    results = []
    for d in chats_collection.where("userId", "==", user).stream():
        data = d.to_dict()
        # History is encrypted string. We don't decrypt full history for the sidebar list to save CPU.
        # We just return the metadata.
        results.append({
            "id": d.id, 
            "name": data.get("name"), 
            "type": data.get("type"), 
            "timestamp": data.get("timestamp")
        })
    return results

@app.get("/chats/{cid}")
async def get_chat_by_id(cid: str, user: str = Depends(get_current_user)):
    doc = chats_collection.document(cid).get()
    if not doc.exists:
        raise HTTPException(404, "Chat not found")
    data = doc.to_dict()
    if data.get("userId") != user:
        raise HTTPException(403, "Unauthorized access to this chat")
    
    # DECRYPT HISTORY HERE
    if "history" in data:
        data["history"] = decrypt_data(data["history"])
        
    return {"id": doc.id, **data}

@app.post("/chats")
async def save_chat(chat: ChatData, user: str = Depends(get_current_user)):
    d = chat.dict(exclude_unset=True)
    d["userId"] = user
    
    # ENCRYPT HISTORY BEFORE SAVING
    if "history" in d:
        d["history"] = encrypt_data(d["history"])

    doc_ref = chats_collection.document(chat.id) if chat.id else chats_collection.document()
    d["id"] = doc_ref.id
    doc_ref.set(d)
    return {"id": doc_ref.id}

@app.delete("/chats/{cid}")
async def del_chat(cid: str, user: str = Depends(get_current_user)):
    doc = chats_collection.document(cid).get()
    if doc.exists and doc.to_dict().get("userId") == user:
        chats_collection.document(cid).delete()
        return {"ok": True}
    raise HTTPException(403, "Unauthorized")

# --- EXTERNAL API ---
@app.post("/api/v1/chat")
async def external_chat(req: ApiChatRequest, x_api_key: str = Header(None)):
    if not manager.local_worker: raise HTTPException(503, "Worker offline")
    user_id = None
    for doc in users_collection.stream():
        if x_api_key in doc.to_dict().get("api_keys", {}):
            user_id = doc.id; break
    if not user_id: raise HTTPException(401, "Invalid Key")
    
    allowed, limit_msg = await check_rate_limit(user_id, source="api")
    if not allowed: raise HTTPException(429, limit_msg)
    
    req_id = f"api_req_{uuid.uuid4().hex}"
    loop = asyncio.get_running_loop()
    fut = loop.create_future()
    pending_api_responses[req_id] = {"future": fut, "buffer": ""}
    
    payload = {"type": "general_chat", "user_id": req_id, "data": {"question": req.message, "history": req.history, "model": "advanced", "enable_web_search": True}}
    
    try:
        await manager.send_to_worker(json.dumps(payload))
        answer = await asyncio.wait_for(fut, timeout=120)
        return {"response": answer, "model": "PrivAI-Core"}
    except: raise HTTPException(504, "Worker Timeout")
    finally: 
        if req_id in pending_api_responses: del pending_api_responses[req_id]

# --- WEBSOCKETS ---
@app.websocket("/ws/worker")
async def ws_worker(ws: WebSocket):
    await ws.accept()
    try:
        auth_msg = await ws.receive_text()
        auth = json.loads(auth_msg)
        if auth.get("secret") != WORKER_SECRET_KEY:
            print("Worker failed auth.")
            await ws.close(); return
        
        await manager.connect_worker(ws)
        print("Worker connected.")
        
        async for msg in ws.iter_text():
            await manager.send_to_client(msg)
    except Exception as e:
        print(f"Worker WebSocket error: {e}")
    finally:
        await manager.disconnect_worker()
        print("Worker disconnected.")

@app.websocket("/ws")
async def ws_web(ws: WebSocket):
    await ws.accept()
    token = ws.query_params.get("token")
    user = f"guest_{uuid.uuid4().hex[:6]}"
    
    if token:
        try: 
            user = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])["sub"]
        except: 
            pass # Fallback to guest if token is invalid
    
    await manager.connect_web(ws, user)
    try:
        async for msg_str in ws.iter_text():
            d = json.loads(msg_str)
            msg_type = d.get("type")
            
            # --- RATE LIMIT CHECKS ---
            if msg_type in ["ask", "general_chat", "general_chat_with_image"]:
                # 1. Standard User Rate Limit
                await check_rate_limit(user, source="web")
                
                # 2. Deep Think Specific Limit
                requested_model = d.get("data", {}).get("model")
                if requested_model == "deep":
                    allowed, reason = await check_deep_think_limit(user)
                    if not allowed:
                        await ws.send_text(json.dumps({
                            "type": "error", 
                            "user_id": user, 
                            "data": reason, 
                            "target": d.get("target", "aichat")
                        }))
                        continue

            d["user_id"] = user
            await manager.send_to_worker(json.dumps(d))
    except Exception as e:
        pass
    finally:
        manager.disconnect_web(user)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    use_ssl = SSL_CERTFILE and SSL_KEYFILE and not os.environ.get("RENDER")
    uvicorn.run(
        app, 
        host="0.0.0.0", 
        port=port, 
        ssl_certfile=SSL_CERTFILE if use_ssl else None, 
        ssl_keyfile=SSL_KEYFILE if use_ssl else None
    )

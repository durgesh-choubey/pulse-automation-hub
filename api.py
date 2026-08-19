from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
from pydantic import BaseModel
from cryptography.fernet import Fernet
import subprocess, json, os, sys, datetime, time, hashlib, secrets, shutil

try:
    import win32com.client
except:
    win32com = None

app = FastAPI(title="PULSE Automation Hub")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ── Paths ──────────────────────────────────────────────────────────────────────
# Always resolve paths relative to api.py location — not the working directory
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DATA_DIR        = os.path.join(BASE_DIR, "data")
SCRIPTS_DIR     = os.path.join(BASE_DIR, "scripts")
JOB_FILE        = os.path.join(BASE_DIR, "jobs.json")
USERS_FILE      = os.path.join(DATA_DIR, "users.json")
VAULT_FILE      = os.path.join(DATA_DIR, "vault.json")
LOGS_FILE       = os.path.join(DATA_DIR, "run_logs.json")
KEY_FILE        = os.path.join(DATA_DIR, "vault.key")
DASHBOARDS_FILE = os.path.join(DATA_DIR, "dashboards.json")
ENTITIES_FILE   = os.path.join(DATA_DIR, "entities.json")
SCRIPT_PERMS_FILE = os.path.join(DATA_DIR, "script_permissions.json")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(SCRIPTS_DIR, exist_ok=True)
print(f"[PULSE] Project root: {BASE_DIR}")
print(f"[PULSE] Data folder:  {DATA_DIR}")

# ── Copilot agent URL ─────────────────────────────────────────────────────────
SLA_KPI_URL = "https://copilotstudio.microsoft.com/YOUR_AGENT_URL_HERE"

# ── Session file — written on login, read by VBS macros ───────────────────────
SESSION_FILE      = os.path.join(DATA_DIR, "pulse_session.json")
SESSION_CREDS_FILE= os.path.join(DATA_DIR, "session_creds.bin")
CRED_ACCESS_LOG   = os.path.join(DATA_DIR, "credential_access.log")

# ── In-memory session store ────────────────────────────────────────────────────
# { token: { username, expires_at, re_encrypted_creds: {portal: encrypted_blob} } }
# Never written to disk — wiped on server restart or expiry
_SESSIONS: dict = {}
SESSION_TTL_HOURS = 8

def _clean_expired_sessions():
    now = datetime.datetime.now()
    expired = [t for t, s in _SESSIONS.items() if s["expires_at"] < now]
    for t in expired:
        del _SESSIONS[t]
        print(f"[PULSE] Session expired: {t[:8]}...")

def _log_cred_access(username: str, portal: str, method: str):
    """Audit log — every credential access recorded."""
    entry = f"{datetime.datetime.now().isoformat()} | {method} | user={username} | portal={portal}"
    with open(CRED_ACCESS_LOG, "a") as f:
        f.write(entry)
    print(f"[PULSE] CRED ACCESS: {entry.strip()}")

# ── Server-side encryption (PULSE login passwords only) ───────────────────────
# Vault entries are encrypted CLIENT-SIDE using master password + PBKDF2.
# Server never sees plaintext vault passwords or the master password.
# The fernet key is only used for PULSE login password hashing fallback.
def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()

# Legacy fernet — kept only for snow_downloader.py server-side report downloads
# which need to decrypt vault on the server to make HTTP requests
def get_fernet():
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return Fernet(f.read())

def encrypt(t):
    """Server-side encrypt — only used for snow report downloader, not vault UI entries."""
    return get_fernet().encrypt(t.encode()).decode()

def decrypt(t):
    """Server-side decrypt — only used for snow report downloader."""
    return get_fernet().decrypt(t.encode()).decode()

# ── Script type detection ──────────────────────────────────────────────────────
def detect_type(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    return {"py": "Python", "vbs": "VBScript", "xlsm": "Excel Macro", "xls": "Excel Macro", "xlsx": "Excel Macro"}.get(ext.lstrip("."), "Other")

def get_ext(filename: str) -> str:
    return os.path.splitext(filename)[1].lower().lstrip(".")

# ── Script descriptions ────────────────────────────────────────────────────────
SCRIPT_DESCRIPTIONS = {
    "DEX Report Download.vbs":     "Downloads DEX performance report from ServiceNow",
    "Run Power BI EOD Report.vbs": "Triggers Power BI End-of-Day report refresh and exports PDF",
    "run_excel.py":                "Runs Excel automation to consolidate data from multiple workbooks",
    "script2.py":                  "Processes and transforms raw data from source systems",
    "test.py":                     "Test script for validating pipeline connectivity",
    "test.vbs":                    "VBScript test for COM object validation",
}
def get_description(name: str, custom_desc: str = "") -> str:
    if custom_desc:
        return custom_desc
    return SCRIPT_DESCRIPTIONS.get(name, f"Automation script — {name}")

# ── Entities ──────────────────────────────────────────────────────────────────
def load_entities():
    if not os.path.exists(ENTITIES_FILE):
        defaults = [
            {"id": "gosp",   "name": "GOSP",   "description": "GOSP entity scripts",   "color": "#3d8ef0", "created_at": datetime.datetime.now().isoformat()},
            {"id": "credem", "name": "CREDEM", "description": "CREDEM entity scripts", "color": "#00c57a", "created_at": datetime.datetime.now().isoformat()},
            {"id": "iccrea", "name": "ICCREA", "description": "ICCREA entity scripts", "color": "#f0a030", "created_at": datetime.datetime.now().isoformat()},
        ]
        with open(ENTITIES_FILE, "w") as f:
            json.dump(defaults, f, indent=2)
        # Create folders
        for e in defaults:
            os.makedirs(os.path.join(SCRIPTS_DIR, e["name"]), exist_ok=True)
    with open(ENTITIES_FILE) as f:
        return json.load(f)

def save_entities(entities):
    with open(ENTITIES_FILE, "w") as f:
        json.dump(entities, f, indent=2)

# ── Users ──────────────────────────────────────────────────────────────────────
def load_users():
    if not os.path.exists(USERS_FILE):
        defaults = [
            {"username": "admin", "password": hash_password("admin123"), "role": "admin"},
            {"username": "user1", "password": hash_password("pulse123"),  "role": "user"},
        ]
        with open(USERS_FILE, "w") as f:
            json.dump(defaults, f, indent=2)
        print("[PULSE] Created default users: admin/admin123, user1/pulse123")
    with open(USERS_FILE) as f:
        return json.load(f)

def verify_user(username, password):
    h = hash_password(password)
    for u in load_users():
        if u["username"] == username and u["password"] == h:
            return u
    return None

# ── Vault ──────────────────────────────────────────────────────────────────────
def load_vault():
    if not os.path.exists(VAULT_FILE): return []
    try:
        with open(VAULT_FILE) as f:
            data = f.read().strip()
            if not data:
                return []
            return json.loads(data)
    except (json.JSONDecodeError, ValueError):
        print("[PULSE] vault.json corrupted or empty — resetting to empty list")
        with open(VAULT_FILE, "w") as f:
            json.dump([], f)
        return []

def save_vault(e):
    with open(VAULT_FILE, "w") as f: json.dump(e, f, indent=2)

# ── Logs ───────────────────────────────────────────────────────────────────────
def load_logs():
    if not os.path.exists(LOGS_FILE): return []
    try:
        with open(LOGS_FILE) as f:
            data = f.read().strip()
            return json.loads(data) if data else []
    except (json.JSONDecodeError, ValueError):
        print("[PULSE] run_logs.json corrupted — resetting")
        with open(LOGS_FILE, "w") as f: json.dump([], f)
        return []

def save_log(entry):
    logs = load_logs()
    logs.insert(0, entry)
    with open(LOGS_FILE, "w") as f: json.dump(logs[:500], f, indent=2)

# ── Dashboards ─────────────────────────────────────────────────────────────────
def load_dashboards():
    if not os.path.exists(DASHBOARDS_FILE):
        defaults = [{"id": secrets.token_hex(4), "name": f"Dashboard {i+1}", "url": "", "description": "Power BI Dashboard", "active": False} for i in range(10)]
        with open(DASHBOARDS_FILE, "w") as f: json.dump(defaults, f, indent=2)
    try:
        with open(DASHBOARDS_FILE) as f:
            data = f.read().strip()
            return json.loads(data) if data else []
    except (json.JSONDecodeError, ValueError):
        return []

def save_dashboards(d):
    with open(DASHBOARDS_FILE, "w") as f: json.dump(d, f, indent=2)

# ── Script index ───────────────────────────────────────────────────────────────
# Each script entry in the index stores metadata so we don't have to scan folders every time
SCRIPT_INDEX_FILE = os.path.join(DATA_DIR, "script_index.json")

def load_script_index():
    if not os.path.exists(SCRIPT_INDEX_FILE): return []
    with open(SCRIPT_INDEX_FILE) as f: return json.load(f)

def save_script_index(index):
    with open(SCRIPT_INDEX_FILE, "w") as f: json.dump(index, f, indent=2)

def rebuild_script_index():
    """Recursively scan all entity folders (including subfolders) and rebuild the index."""
    entities = load_entities()
    logs = load_logs()
    old_index = load_script_index()  # keep existing metadata (descriptions, ids)
    index = []
    seen_paths = set()

    def _make_entry(fname, fpath, entity_name, entity_id, entity_color, subfolder=""):
        """Build one index entry, preserving id and description from old index."""
        ext = get_ext(fname)
        last = next((l for l in logs if l["script"] == fname and l.get("entity") == entity_name), None)
        existing = next((s for s in old_index if s["path"] == fpath or
                         (s["name"] == fname and s["entity"] == entity_name)), None)
        display_name = f"{subfolder}/{fname}" if subfolder else fname
        return {
            "id":           existing["id"] if existing else secrets.token_hex(6),
            "name":         fname,
            "display_name": display_name,
            "subfolder":    subfolder,
            "entity":       entity_name,
            "entity_id":    entity_id,
            "entity_color": entity_color,
            "ext":          ext,
            "type":         detect_type(fname),
            "path":         fpath,
            "description":  existing["description"] if existing else get_description(fname),
            "last_run":     last["finished_at"] if last else None,
            "last_status":  last["status"] if last else None,
            "last_duration":last["duration_sec"] if last else None,
        }

    # Walk each entity folder recursively (catches all subfolders)
    for entity in entities:
        root_folder = os.path.join(SCRIPTS_DIR, entity["name"])
        os.makedirs(root_folder, exist_ok=True)
        for dirpath, dirnames, filenames in os.walk(root_folder):
            # Subfolder name relative to entity root (empty string = root level)
            subfolder = os.path.relpath(dirpath, root_folder)
            if subfolder == ".":
                subfolder = ""
            for fname in sorted(filenames):
                ext = get_ext(fname)
                if ext in ["py", "vbs", "xlsm", "xls"]:
                    fpath = os.path.join(dirpath, fname)
                    if fpath in seen_paths:
                        continue
                    seen_paths.add(fpath)
                    index.append(_make_entry(
                        fname, fpath,
                        entity["name"], entity["id"], entity["color"],
                        subfolder
                    ))

    # Also scan root scripts/ folder for legacy unassigned scripts
    for fname in sorted(os.listdir(SCRIPTS_DIR)):
        fpath = os.path.join(SCRIPTS_DIR, fname)
        if os.path.isfile(fpath) and fpath not in seen_paths:
            ext = get_ext(fname)
            if ext in ["py", "vbs", "xlsm", "xls"]:
                seen_paths.add(fpath)
                last = next((l for l in logs if l["script"] == fname and not l.get("entity")), None)
                existing = next((s for s in old_index if s["name"] == fname and s["entity"] == "Unassigned"), None)
                index.append({
                    "id":           existing["id"] if existing else secrets.token_hex(6),
                    "name":         fname,
                    "display_name": fname,
                    "subfolder":    "",
                    "entity":       "Unassigned",
                    "entity_id":    "unassigned",
                    "entity_color": "#5a6478",
                    "ext":          ext,
                    "type":         detect_type(fname),
                    "path":         fpath,
                    "description":  existing["description"] if existing else get_description(fname),
                    "last_run":     last["finished_at"] if last else None,
                    "last_status":  last["status"] if last else None,
                    "last_duration":last["duration_sec"] if last else None,
                })

    save_script_index(index)
    return index


# ── Script permissions ─────────────────────────────────────────────────────────
def load_script_perms():
    if not os.path.exists(SCRIPT_PERMS_FILE): return {}
    try:
        with open(SCRIPT_PERMS_FILE) as f:
            data = f.read().strip()
            return json.loads(data) if data else {}
    except: return {}

def save_script_perms(perms):
    with open(SCRIPT_PERMS_FILE, "w") as f:
        json.dump(perms, f, indent=2)

def get_script_owners(script_id: str) -> list:
    perms = load_script_perms()
    return perms.get(script_id, [])

def user_can_see_script(script_id: str, username: str, role: str) -> bool:
    """Admin sees everything. Users see only scripts assigned to them."""
    if role == "admin": return True
    owners = get_script_owners(script_id)
    if not owners: return False  # unassigned = admin only
    return username in owners

# ── Scheduler ─────────────────────────────────────────────────────────────────
scheduler = BackgroundScheduler()
scheduler.start()

# ── Script runner ─────────────────────────────────────────────────────────────
def run_script(script_path, triggered_by="scheduled", entity=""):
    ext  = os.path.splitext(script_path)[1].lower()
    name = os.path.basename(script_path)
    started_at = datetime.datetime.now().isoformat()
    t0 = time.time()
    stdout = stderr = ""
    success = False
    print(f"[PULSE] ▶ {name} ({triggered_by}) [{entity}]")
    try:
        if ext == ".py":
            r = subprocess.run([sys.executable, script_path], capture_output=True, text=True, timeout=1800)
            stdout, stderr, success = r.stdout, r.stderr, r.returncode == 0
        elif ext == ".vbs":
            r = subprocess.run(["cscript", "//Nologo", script_path], capture_output=True, text=True, timeout=1800)
            stdout, stderr, success = r.stdout, r.stderr, r.returncode == 0
        elif ext in [".xlsm", ".xls", ".xlsx"]:
            r = subprocess.run([sys.executable, os.path.join(SCRIPTS_DIR, "run_excel.py"), script_path], capture_output=True, text=True, timeout=1800)
            stdout, stderr, success = r.stdout, r.stderr, r.returncode == 0
        else:
            stderr = f"Unsupported: {ext}"
    except subprocess.TimeoutExpired:
        stderr = "Script is still running — please wait"
    except Exception as e:
        stderr = str(e)

    duration = round(time.time() - t0, 2)
    save_log({
        "id":           secrets.token_hex(6),
        "script":       name,
        "script_path":  script_path,
        "entity":       entity,
        "description":  get_description(name),
        "triggered_by": triggered_by,
        "started_at":   started_at,
        "finished_at":  datetime.datetime.now().isoformat(),
        "duration_sec": duration,
        "status":       "success" if success else "failed",
        "output":       stdout.strip(),
        "error":        stderr.strip(),
    })
    print(f"[PULSE] {'✓' if success else '✗'} {name} — {duration}s")
    return stdout, stderr, success

# ── Jobs ───────────────────────────────────────────────────────────────────────
def load_jobs():
    try:
        with open(JOB_FILE) as f: jobs = json.load(f)
    except: jobs = []
    for job in jobs:
        try:
            if job.get("type") == "interval":
                scheduler.add_job(run_script, 'interval', minutes=job.get("interval_minutes", 60),
                    args=[job["script"], "scheduled", job.get("entity","")],
                    id=f"{job['script']}_iv_{job.get('interval_minutes')}", replace_existing=True)
            else:
                scheduler.add_job(run_script, 'cron', hour=job["hour"], minute=job["minute"],
                    args=[job["script"], "scheduled", job.get("entity","")],
                    id=f"{job['script']}_{job['hour']}_{job['minute']}", replace_existing=True)
        except Exception as e:
            print(f"[PULSE] Skip {job.get('script')}: {e}")
    print(f"[PULSE] {len(jobs)} jobs loaded")

def append_job(entry):
    try:
        with open(JOB_FILE) as f: jobs = json.load(f)
    except: jobs = []
    jobs.append(entry)
    with open(JOB_FILE, "w") as f: json.dump(jobs, f, indent=4)

# Initialise
load_entities()
load_jobs()
rebuild_script_index()

# ── Pydantic models ────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class VaultEntry(BaseModel):
    portal:             str
    username:           str
    encrypted_password: str = ""
    salt:               str = ""
    iv:                 str = ""
    password:           str = ""
    instance:           str = ""
    notes:              str = ""

class SnowConnectRequest(BaseModel):
    portal: str
    owner:  str = ""   # logged-in username — scopes vault lookup to their credentials

class ScheduleRequest(BaseModel):
    script_id: str
    type: str = "cron"
    hour: int = 9; minute: int = 0
    interval_minutes: int = 60

class UserCreate(BaseModel):
    username: str; password: str; role: str = "user"

class EntityCreate(BaseModel):
    name: str; description: str = ""; color: str = "#3d8ef0"

class EntityUpdate(BaseModel):
    name: str; description: str = ""; color: str = "#3d8ef0"

class DashboardUpdate(BaseModel):
    name: str; url: str; description: str = ""; active: bool = True

class DashboardCreate(BaseModel):
    name: str; url: str = ""; description: str = ""; active: bool = False

class ScriptDescUpdate(BaseModel):
    description: str

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.get("/ui", response_class=HTMLResponse)
def ui():
    with open("templates/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

# ── Auth ───────────────────────────────────────────────────────────────────────
@app.post("/api/login")
def login(body: LoginRequest):
    print(f"[PULSE] Login: {body.username}")
    user = verify_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"success": True, "username": user["username"], "role": user["role"]}

@app.get("/api/users")
def get_users():
    return [{"username": u["username"], "role": u["role"]} for u in load_users()]

@app.post("/api/users")
def create_user(body: UserCreate):
    users = load_users()
    if any(u["username"] == body.username for u in users):
        raise HTTPException(status_code=400, detail="User already exists")
    users.append({"username": body.username, "password": hash_password(body.password), "role": body.role})
    with open(USERS_FILE, "w") as f: json.dump(users, f, indent=2)
    return {"success": True}

@app.delete("/api/users/{username}")
def delete_user(username: str):
    users = [u for u in load_users() if u["username"] != username]
    with open(USERS_FILE, "w") as f: json.dump(users, f, indent=2)
    return {"success": True}

class ChangePwRequest(BaseModel):
    current_password: str
    new_password:     str

@app.post("/api/users/{username}/change-password")
def change_login_password(username: str, body: ChangePwRequest):
    """Any user can change their own PULSE login password after verifying current one."""
    if not body.current_password:
        raise HTTPException(status_code=400, detail="Current password required")
    if not body.new_password or len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if body.current_password == body.new_password:
        raise HTTPException(status_code=400, detail="New password must be different")

    users = load_users()
    user  = next((u for u in users if u["username"] == username), None)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Verify current password
    if user["password"] != hash_password(body.current_password):
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    # Update password
    user["password"] = hash_password(body.new_password)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

    print(f"[PULSE] Password changed for user '{username}'")
    return {"success": True, "message": "Password updated. Please log in again."}

# ── Entities ───────────────────────────────────────────────────────────────────
@app.get("/api/entities")
def get_entities():
    entities = load_entities()
    index = load_script_index()
    for e in entities:
        e["script_count"] = len([s for s in index if s["entity"] == e["name"]])
    return entities

@app.post("/api/entities")
def create_entity(body: EntityCreate):
    entities = load_entities()
    name_clean = body.name.strip().upper()
    if any(e["name"].upper() == name_clean for e in entities):
        raise HTTPException(status_code=400, detail="Entity already exists")
    new_entity = {
        "id":          name_clean.lower(),
        "name":        name_clean,
        "description": body.description,
        "color":       body.color,
        "created_at":  datetime.datetime.now().isoformat(),
    }
    entities.append(new_entity)
    save_entities(entities)
    os.makedirs(os.path.join(SCRIPTS_DIR, name_clean), exist_ok=True)
    return {"success": True, "entity": new_entity}

@app.put("/api/entities/{entity_id}")
def update_entity(entity_id: str, body: EntityUpdate):
    entities = load_entities()
    for e in entities:
        if e["id"] == entity_id:
            e["description"] = body.description
            e["color"] = body.color
            save_entities(entities)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Entity not found")

@app.delete("/api/entities/{entity_id}")
def delete_entity(entity_id: str):
    entities = load_entities()
    entity = next((e for e in entities if e["id"] == entity_id), None)
    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")
    index = load_script_index()
    if any(s["entity"] == entity["name"] for s in index):
        raise HTTPException(status_code=400, detail=f"Cannot delete — {entity['name']} has scripts assigned. Reassign or delete scripts first.")
    entities = [e for e in entities if e["id"] != entity_id]
    save_entities(entities)
    # Don't delete folder — keep as backup
    return {"success": True}

# ── Scripts ────────────────────────────────────────────────────────────────────
@app.get("/api/scripts")
def list_scripts(entity: str = None, owner: str = ""):
    """
    Admin gets all scripts.
    Regular users only get scripts assigned to them via /api/scripts/{id}/assign.
    """
    index = rebuild_script_index()
    if entity:
        index = [s for s in index if s["entity"].lower() == entity.lower()]

    if owner:
        # Find role of this user
        users = load_users()
        user = next((u for u in users if u["username"] == owner), None)
        role = user["role"] if user else "user"
        if role != "admin":
            index = [s for s in index if user_can_see_script(s["id"], owner, role)]

    return index

@app.get("/api/scripts/legacy")
def list_scripts_legacy():
    return sorted([f for f in os.listdir(SCRIPTS_DIR) if f.endswith((".py",".vbs",".xlsm"))]) if os.path.exists(SCRIPTS_DIR) else []

@app.post("/api/scripts/upload")
async def upload_script(
    file: UploadFile = File(...),
    entity: str = Form(...),
    description: str = Form(""),
):
    entities = load_entities()
    entity_obj = next((e for e in entities if e["name"].upper() == entity.upper() or e["id"] == entity.lower()), None)
    if not entity_obj:
        raise HTTPException(status_code=400, detail=f"Entity '{entity}' not found")

    folder = os.path.join(SCRIPTS_DIR, entity_obj["name"])
    os.makedirs(folder, exist_ok=True)

    filename = file.filename
    ext = get_ext(filename)
    if ext not in ["py", "vbs", "xlsm", "xls"]:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: .{ext}. Allowed: .py .vbs .xlsm")

    save_path = os.path.join(folder, filename)
    with open(save_path, "wb") as f:
        content = await file.read()
        f.write(content)

    # Add to index
    index = load_script_index()
    existing = next((s for s in index if s["name"] == filename and s["entity"] == entity_obj["name"]), None)
    if not existing:
        index.append({
            "id":           secrets.token_hex(6),
            "name":         filename,
            "entity":       entity_obj["name"],
            "entity_id":    entity_obj["id"],
            "entity_color": entity_obj["color"],
            "ext":          ext,
            "type":         detect_type(filename),
            "path":         save_path,
            "description":  description or get_description(filename),
            "last_run":     None,
            "last_status":  None,
            "last_duration":None,
        })
        save_script_index(index)

    return {
        "success": True,
        "name": filename,
        "entity": entity_obj["name"],
        "type": detect_type(filename),
        "path": save_path,
    }

@app.delete("/api/scripts/{script_id}")
def delete_script(script_id: str):
    index = load_script_index()
    script = next((s for s in index if s["id"] == script_id), None)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    if os.path.exists(script["path"]):
        os.remove(script["path"])
    index = [s for s in index if s["id"] != script_id]
    save_script_index(index)
    return {"success": True}

@app.get("/api/scripts/{script_id}/owners")
def get_script_owners_api(script_id: str):
    """Returns list of users assigned to this script."""
    return {"script_id": script_id, "owners": get_script_owners(script_id)}

@app.post("/api/scripts/{script_id}/assign")
def assign_script_to_user(script_id: str, body: dict):
    """Admin assigns a script to a user. User can now see and run it."""
    username = body.get("username","").strip()
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    # Verify user exists
    users = load_users()
    if not any(u["username"] == username for u in users):
        raise HTTPException(status_code=404, detail=f"User '{username}' not found")
    perms = load_script_perms()
    if script_id not in perms:
        perms[script_id] = []
    if username not in perms[script_id]:
        perms[script_id].append(username)
        save_script_perms(perms)
    print(f"[PULSE] Script {script_id} assigned to '{username}'")
    return {"success": True, "owners": perms[script_id]}

@app.delete("/api/scripts/{script_id}/assign/{username}")
def remove_script_assignment(script_id: str, username: str):
    """Admin removes a user's access to a script."""
    perms = load_script_perms()
    if script_id in perms and username in perms[script_id]:
        perms[script_id].remove(username)
        save_script_perms(perms)
    return {"success": True}

@app.patch("/api/scripts/{script_id}/description")
def update_script_description(script_id: str, body: ScriptDescUpdate):
    index = load_script_index()
    for s in index:
        if s["id"] == script_id:
            s["description"] = body.description
            save_script_index(index)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Script not found")

# ── Run ───────────────────────────────────────────────────────────────────────
@app.post("/api/run/{script_id}")
def api_run(script_id: str):
    index = load_script_index()
    script = next((s for s in index if s["id"] == script_id), None)
    if not script:
        # fallback: treat script_id as filename in root scripts dir
        fp = os.path.join(SCRIPTS_DIR, script_id)
        if not os.path.exists(fp):
            raise HTTPException(status_code=404, detail="Script not found")
        out, err, ok = run_script(fp, "manual", "")
        return {"success": ok, "output": out, "error": err}
    out, err, ok = run_script(script["path"], "manual", script["entity"])
    return {"script": script["name"], "entity": script["entity"], "success": ok, "output": out, "error": err}

# Keep legacy route
@app.post("/run/{script_name}")
def run_now(script_name: str):
    fp = os.path.join(SCRIPTS_DIR, script_name)
    if not os.path.exists(fp): return {"error": "Script not found"}
    out, err, ok = run_script(fp, "manual", "")
    return {"message": f"{script_name} executed", "output": out, "error": err, "success": ok}

# ── Schedule ──────────────────────────────────────────────────────────────────
@app.post("/api/schedule")
def api_schedule(body: ScheduleRequest):
    index = load_script_index()
    script = next((s for s in index if s["id"] == body.script_id), None)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")
    fp = script["path"]
    entity = script["entity"]
    if body.type == "interval":
        scheduler.add_job(run_script, 'interval', minutes=body.interval_minutes,
            args=[fp, "scheduled", entity],
            id=f"{fp}_iv_{body.interval_minutes}", replace_existing=True)
        append_job({"script": fp, "entity": entity, "type": "interval", "interval_minutes": body.interval_minutes, "script_name": script["name"]})
        return {"success": True, "message": f"{script['name']} runs every {body.interval_minutes} minutes"}
    else:
        scheduler.add_job(run_script, 'cron', hour=body.hour, minute=body.minute,
            args=[fp, "scheduled", entity],
            id=f"{fp}_{body.hour}_{body.minute}", replace_existing=True)
        append_job({"script": fp, "entity": entity, "type": "cron", "hour": body.hour, "minute": body.minute, "script_name": script["name"]})
        return {"success": True, "message": f"{script['name']} daily at {body.hour:02d}:{body.minute:02d}"}

@app.get("/api/jobs")
def get_jobs():
    try:
        with open(JOB_FILE) as f: return json.load(f)
    except: return []

# ── Logs ───────────────────────────────────────────────────────────────────────
@app.get("/api/logs")
def get_logs(limit: int = 100, entity: str = None):
    logs = load_logs()[:limit]
    if entity:
        logs = [l for l in logs if l.get("entity","").lower() == entity.lower()]
    return logs

@app.delete("/api/logs")
def clear_logs():
    with open(LOGS_FILE, "w") as f: json.dump([], f)
    return {"success": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats():
    logs = load_logs()
    today = datetime.date.today().isoformat()
    tl = [l for l in logs if l["started_at"][:10] == today]
    index = load_script_index()
    try:
        with open(JOB_FILE) as f: jobs = json.load(f)
    except: jobs = []
    entities = load_entities()
    return {
        "total_scripts":  len(index),
        "total_jobs":     len(jobs),
        "total_entities": len(entities),
        "runs_today":     len(tl),
        "failed_today":   sum(1 for l in tl if l["status"] == "failed"),
        "success_today":  sum(1 for l in tl if l["status"] == "success"),
        "last_run":       logs[0]["finished_at"] if logs else None,
        "last_status":    logs[0]["status"] if logs else None,
    }

# ── Vault ─────────────────────────────────────────────────────────────────────
# Each vault entry is owned by the user who created it (owner field).
# Users only see and manage their own entries.
# Passwords are NEVER returned in any API response — not even to admin.

class VaultOwnerRequest(BaseModel):
    owner: str  # logged-in username passed from frontend

@app.get("/api/vault")
def get_vault(owner: str = ""):
    """Return vault entries for this owner. Returns encrypted blob for browser decryption."""
    entries = load_vault()
    if owner:
        entries = [e for e in entries if e.get("owner","") == owner]
    return [
        {
            "id":                e["id"],
            "portal":            e["portal"],
            "username":          e["username"],
            "instance":          e.get("instance",""),
            "notes":             e.get("notes",""),
            "owner":             e.get("owner",""),
            # Return encrypted blob + salt + iv — browser decrypts with master password
            # Server cannot decrypt this — it has no master password
            "encrypted_password": e.get("encrypted_password",""),
            "salt":              e.get("salt",""),
            "iv":                e.get("iv",""),
            # Never return legacy plain password field
        }
        for e in entries
    ]

@app.post("/api/vault")
def add_vault(body: VaultEntry, owner: str = ""):
    if not body.portal.strip():
        raise HTTPException(status_code=400, detail="Portal name is required")
    if not body.username.strip():
        raise HTTPException(status_code=400, detail="Username is required")
    # encrypted_password can be empty if user skipped master password setup
    # In that case we accept the entry but warn it has no encryption layer

    entries = load_vault()
    existing = [e for e in entries
                if e["portal"].lower() == body.portal.lower()
                and e.get("owner","") == owner]

    e = {
        "id":                secrets.token_hex(6),
        "portal":            body.portal.strip(),
        "username":          body.username.strip(),
        # Client-side encrypted — server cannot decrypt without master password
        "encrypted_password": body.encrypted_password,
        "salt":              body.salt,
        "iv":                body.iv,
        # Legacy server-side password field — empty for all new UI entries
        "password":          "",
        "instance":          body.instance.strip(),
        "notes":             body.notes.strip(),
        "owner":             owner,
    }
    entries.append(e)

    try:
        save_vault(entries)
    except Exception as ex:
        raise HTTPException(status_code=500, detail=f"Could not save vault: {str(ex)}")

    print(f"[PULSE] Vault: '{e['portal']}' saved by '{owner}' (client-encrypted, server blind)")
    return {
        "success":   True,
        "id":        e["id"],
        "portal":    e["portal"],
        "duplicate": len(existing) > 0,
    }

@app.patch("/api/vault/{eid}/password")
def change_vault_password(eid: str, body: dict, owner: str = ""):
    """Update vault entry with new client-encrypted password blob."""
    entries = load_vault()
    entry = next((e for e in entries if e["id"] == eid), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if entry.get("owner","") != owner:
        raise HTTPException(status_code=403, detail="You can only change your own credentials")

    new_enc = body.get("encrypted_password","").strip()
    new_salt = body.get("salt","").strip()
    new_iv   = body.get("iv","").strip()

    if not new_enc or not new_salt or not new_iv:
        raise HTTPException(status_code=400, detail="encrypted_password, salt and iv are required")

    entry["encrypted_password"] = new_enc
    entry["salt"]               = new_salt
    entry["iv"]                 = new_iv
    entry["password"]           = ""  # clear any legacy plain password
    save_vault(entries)
    print(f"[PULSE] Vault: password re-encrypted for '{entry['portal']}' by '{owner}'")
    return {"success": True}

@app.delete("/api/vault/{eid}")
def del_vault(eid: str, owner: str = ""):
    entries = load_vault()
    entry = next((e for e in entries if e["id"] == eid), None)
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    if entry.get("owner","") != owner:
        raise HTTPException(status_code=403, detail="You can only delete your own credentials")
    save_vault([e for e in entries if e["id"] != eid])
    print(f"[PULSE] Vault: '{entry['portal']}' deleted by '{owner}'")
    return {"success": True}

# ── Snow Connect ──────────────────────────────────────────────────────────────
@app.post("/api/snow/connect")
def snow_connect(body: SnowConnectRequest):
    # Accept optional owner to scope lookup to current user's credentials
    owner = getattr(body, "owner", "") or ""
    entries = load_vault()
    # Filter by owner first if provided, then fall back to any matching entry
    scoped = [e for e in entries if e["portal"].lower() == body.portal.lower()
              and (not owner or e.get("owner","") == owner)]
    entry = scoped[0] if scoped else next(
        (e for e in entries if e["portal"].lower() == body.portal.lower()), None)
    if not entry:
        raise HTTPException(status_code=404, detail="No vault entry for this portal")

    username = entry["username"]
    password = decrypt(entry["password"])
    instance = entry.get("instance", "").strip().rstrip("/")

    if not instance:
        return {"connected": False, "error": "No instance URL saved in vault for this portal"}

    # Normalise — ensure https://
    if not instance.startswith("http"):
        instance = "https://" + instance

    # Try requests first (better SSL handling), fall back to urllib
    test_urls = [
        f"{instance}/api/now/table/incident?sysparm_limit=1&sysparm_fields=number",
        f"{instance}/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name",
    ]

    try:
        import requests as req_lib
        for url in test_urls:
            try:
                r = req_lib.get(url, auth=(username, password),
                                headers={"Accept": "application/json"},
                                timeout=12, verify=True)
                if r.status_code == 200:
                    return {"connected": True, "instance": instance, "username": username}
                if r.status_code == 401:
                    return {"connected": False, "error": "Wrong username or password (401 Unauthorized)"}
                if r.status_code == 403:
                    return {"connected": False, "error": "Credentials OK but access denied (403). Check your SNOW role/permissions."}
                if r.status_code == 404:
                    return {"connected": False, "error": f"Instance URL not found (404). Check: {instance}"}
            except req_lib.exceptions.SSLError:
                # Retry without SSL verification (some corporate instances)
                try:
                    import urllib3; urllib3.disable_warnings()
                    r = req_lib.get(url, auth=(username, password),
                                    headers={"Accept": "application/json"},
                                    timeout=12, verify=False)
                    if r.status_code == 200:
                        return {"connected": True, "instance": instance, "username": username, "note": "SSL verification bypassed"}
                    if r.status_code == 401:
                        return {"connected": False, "error": "Wrong username or password (401)"}
                except Exception as ex2:
                    return {"connected": False, "error": f"SSL error even after bypass: {str(ex2)}"}
            except req_lib.exceptions.ConnectionError as ce:
                return {"connected": False, "error": f"Cannot reach {instance} — check VPN is active and instance URL is correct. Detail: {str(ce)[:120]}"}
            except req_lib.exceptions.Timeout:
                return {"connected": False, "error": f"Connection timed out to {instance} — VPN may be blocking or instance is unreachable"}
            except Exception as ex:
                return {"connected": False, "error": f"Unexpected error: {str(ex)[:150]}"}
        return {"connected": False, "error": "Could not connect — check VPN, instance URL and credentials"}

    except ImportError:
        # requests not installed — fall back to urllib
        import urllib.request, urllib.error, base64, ssl
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for url in test_urls:
            try:
                req = urllib.request.Request(url)
                req.add_header("Authorization", f"Basic {creds}")
                req.add_header("Accept", "application/json")
                with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
                    if resp.status == 200:
                        return {"connected": True, "instance": instance, "username": username}
            except urllib.error.HTTPError as e:
                if e.code == 401: return {"connected": False, "error": "Wrong username or password (401)"}
                if e.code == 403: return {"connected": False, "error": "Access denied (403) — check SNOW role"}
                continue
            except Exception as ex:
                return {"connected": False, "error": f"Network error — check VPN. Detail: {str(ex)[:120]}"}
        return {"connected": False, "error": "Cannot reach instance — ensure VPN is active"}

@app.get("/api/snow/autoconnect")
def snow_autoconnect(owner: str = ""):
    entries = load_vault()
    keywords = ["snow","servicenow","generali","service-now","iccrea","credem","gosp"]
    # Prefer current user's entry, fall back to any SNOW entry
    if owner:
        entry = next((e for e in entries if e.get("owner","") == owner
                      and any(k in e["portal"].lower() for k in keywords)), None)
    else:
        entry = None
    if not entry:
        entry = next((e for e in entries if any(k in e["portal"].lower() for k in keywords)), None)
    if not entry:
        return {"connected": False, "error": "No ServiceNow entry found in vault — add one first"}
    class _B:
        portal = entry["portal"]
        owner_val = owner
    b = _B()
    setattr(b, "owner", owner)
    return snow_connect(b)


# ── Session token system ───────────────────────────────────────────────────────
class SessionWrite(BaseModel):
    username: str

class ActivateCredsRequest(BaseModel):
    token:          str
    portal:         str
    encrypted_cred: str
    nonce:          str
    username_hint:  str = ""
    instance:       str = ""

@app.post("/api/session/write")
def write_session(body: SessionWrite):
    _clean_expired_sessions()
    token   = secrets.token_hex(32)
    expires = datetime.datetime.now() + datetime.timedelta(hours=SESSION_TTL_HOURS)
    _SESSIONS[token] = {"username": body.username, "expires_at": expires, "creds": {}}
    with open(SESSION_FILE, "w") as f:
        json.dump({"username": body.username, "token": token,
                   "written_at": datetime.datetime.now().isoformat(),
                   "expires_at": expires.isoformat()}, f, indent=2)
    print(f"[PULSE] Session created: {body.username} | token={token[:8]}... | expires={expires.strftime('%H:%M')}")
    return {"success": True, "token": token, "expires_at": expires.isoformat()}

@app.get("/api/session/current")
def read_session():
    if not os.path.exists(SESSION_FILE):
        return {"username": "", "active": False}
    with open(SESSION_FILE) as f:
        data = json.load(f)
    token  = data.get("token","")
    active = token in _SESSIONS and _SESSIONS[token]["expires_at"] > datetime.datetime.now()
    return {"username": data.get("username",""), "active": active,
            "expires_at": data.get("expires_at","")}

@app.post("/api/session/activate-creds")
def activate_creds(body: ActivateCredsRequest):
    """
    Browser decrypts vault credential with master password,
    re-encrypts with session token, sends here.
    Server stores re-encrypted blob in MEMORY ONLY — never on disk.
    """
    _clean_expired_sessions()
    session = _SESSIONS.get(body.token)
    if not session or session["expires_at"] < datetime.datetime.now():
        raise HTTPException(status_code=401, detail="Invalid or expired session. Log in again.")
    session["creds"][body.portal] = {
        "encrypted_cred": body.encrypted_cred,
        "nonce":          body.nonce,
        "username_hint":  body.username_hint,
        "instance":       body.instance,
        "activated_at":   datetime.datetime.now().isoformat(),
    }
    _log_cred_access(session["username"], body.portal, "ACTIVATE")
    return {"success": True, "portal": body.portal}

@app.get("/api/session/credentials")
def get_session_credentials(portal: str = ""):
    """
    Called by VBS macro via HTTP.
    Returns re-encrypted credential blob — VBS decrypts using session token.
    401 if no active session — macro cannot run without user logged in.
    Every access audit logged.
    """
    _clean_expired_sessions()
    if not os.path.exists(SESSION_FILE):
        raise HTTPException(status_code=401,
            detail="No active PULSE session. Log into the portal first.")
    with open(SESSION_FILE) as f:
        sdata = json.load(f)
    token   = sdata.get("token","")
    session = _SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401,
            detail="Session expired. Log into PULSE portal again.")
    if session["expires_at"] < datetime.datetime.now():
        del _SESSIONS[token]
        raise HTTPException(status_code=401, detail="Session expired. Log in again.")
    if not session["creds"]:
        raise HTTPException(status_code=404,
            detail="No credentials activated. Open PULSE vault → click 'Activate for macros'.")
    keywords = [portal.lower(), "generali", "snow", "servicenow", "gosp", "credem", "iccrea"]
    cred = None
    if portal:
        cred = next((v for k,v in session["creds"].items()
                     if any(w in k.lower() for w in keywords)), None)
    if not cred:
        cred = next(iter(session["creds"].values()), None)
    if not cred:
        raise HTTPException(status_code=404, detail=f"No credential found for '{portal}'.")
    _log_cred_access(session["username"], portal or "any", "READ")
    return {
        "token":          token,
        "encrypted_cred": cred["encrypted_cred"],
        "nonce":          cred["nonce"],
        "username_hint":  cred.get("username_hint",""),
        "instance":       cred.get("instance",""),
        "expires_at":     session["expires_at"].isoformat(),
    }

@app.post("/api/session/logout")
def session_logout(body: SessionWrite):
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            data = json.load(f)
        token = data.get("token","")
        if token in _SESSIONS:
            del _SESSIONS[token]
    with open(SESSION_FILE, "w") as f:
        json.dump({"username":"","token":"","active":False}, f)
    return {"success": True}

@app.get("/api/session/audit-log")
def get_audit_log():
    if not os.path.exists(CRED_ACCESS_LOG):
        return {"entries": []}
    with open(CRED_ACCESS_LOG) as f:
        lines = f.readlines()
    return {"entries": [l.strip() for l in lines[-200:]]}

@app.get("/api/sla-url")
def get_sla_url():
    return {"url": SLA_KPI_URL}



# ── Dashboards ────────────────────────────────────────────────────────────────
@app.get("/api/dashboards")
def get_dashboards(): return load_dashboards()

@app.post("/api/dashboards")
def add_dashboard(body: DashboardCreate):
    d = load_dashboards()
    nd = {"id": secrets.token_hex(4), "name": body.name, "url": body.url, "description": body.description, "active": body.active}
    d.append(nd); save_dashboards(d)
    return {"success": True, "id": nd["id"]}

@app.put("/api/dashboards/{did}")
def update_dashboard(did: str, body: DashboardUpdate):
    d = load_dashboards()
    for x in d:
        if x["id"] == did:
            x.update({"name": body.name, "url": body.url, "description": body.description, "active": body.active})
            save_dashboards(d); return {"success": True}
    raise HTTPException(status_code=404, detail="Not found")

@app.delete("/api/dashboards/{did}")
def del_dashboard(did: str):
    save_dashboards([x for x in load_dashboards() if x["id"] != did])
    return {"success": True}

# ── Reassign script to a different entity ─────────────────────────────────────
class ReassignRequest(BaseModel):
    entity: str

@app.patch("/api/scripts/{script_id}/reassign")
def reassign_script(script_id: str, body: ReassignRequest):
    """Move a script file to a different entity folder and update the index."""
    ents = load_entities()
    target = next((e for e in ents if e["name"].upper() == body.entity.upper() or e["id"] == body.entity.lower()), None)
    if not target:
        raise HTTPException(status_code=400, detail=f"Entity '{body.entity}' not found")

    index = load_script_index()
    script = next((s for s in index if s["id"] == script_id), None)
    if not script:
        raise HTTPException(status_code=404, detail="Script not found")

    if script["entity"] == target["name"]:
        return {"success": True, "message": "Already in this entity"}

    new_folder = os.path.join(SCRIPTS_DIR, target["name"])
    os.makedirs(new_folder, exist_ok=True)
    new_path = os.path.join(new_folder, script["name"])

    if os.path.exists(script["path"]):
        shutil.move(script["path"], new_path)

    script["path"]         = new_path
    script["entity"]       = target["name"]
    script["entity_id"]    = target["id"]
    script["entity_color"] = target["color"]
    save_script_index(index)

    return {"success": True, "message": f"{script['name']} moved to {target['name']}"}

# ══════════════════════════════════════════════════════════════════════════════
# SNOW REPORTS — Registry + Direct Download from portal
# ══════════════════════════════════════════════════════════════════════════════
SNOW_REPORTS_FILE = os.path.join(DATA_DIR, "snow_reports.json")
ST_APPS_FILE      = os.path.join(DATA_DIR, "st_apps.json")

def load_snow_reports():
    if not os.path.exists(SNOW_REPORTS_FILE): return []
    with open(SNOW_REPORTS_FILE) as f: return json.load(f)

def save_snow_reports(r):
    with open(SNOW_REPORTS_FILE, "w") as f: json.dump(r, f, indent=2)

class SNOWReportCreate(BaseModel):
    name:        str
    report_id:   str
    fmt:         str = "excel"      # excel / pdf / csv
    entity:      str = ""
    description: str = ""
    output_dir:  str = ""           # leave blank to use downloads/

class SNOWReportUpdate(BaseModel):
    name:        str
    report_id:   str
    fmt:         str = "excel"
    entity:      str = ""
    description: str = ""
    output_dir:  str = ""

@app.get("/api/snow-reports")
def get_snow_reports():
    return load_snow_reports()

@app.post("/api/snow-reports")
def add_snow_report(body: SNOWReportCreate):
    reports = load_snow_reports()
    entry = {
        "id":          secrets.token_hex(6),
        "name":        body.name,
        "report_id":   body.report_id,
        "fmt":         body.fmt,
        "entity":      body.entity,
        "description": body.description,
        "output_dir":  body.output_dir,
        "last_run":    None,
        "last_status": None,
        "last_path":   None,
    }
    reports.append(entry)
    save_snow_reports(reports)
    return {"success": True, "id": entry["id"]}

@app.put("/api/snow-reports/{rid}")
def update_snow_report(rid: str, body: SNOWReportUpdate):
    reports = load_snow_reports()
    for r in reports:
        if r["id"] == rid:
            r.update({"name": body.name, "report_id": body.report_id,
                       "fmt": body.fmt, "entity": body.entity,
                       "description": body.description, "output_dir": body.output_dir})
            save_snow_reports(reports)
            return {"success": True}
    raise HTTPException(status_code=404, detail="Report not found")

@app.delete("/api/snow-reports/{rid}")
def delete_snow_report(rid: str):
    save_snow_reports([r for r in load_snow_reports() if r["id"] != rid])
    return {"success": True}

@app.post("/api/snow-reports/{rid}/download")
def download_snow_report(rid: str):
    """Trigger a report download using vault credentials."""
    reports = load_snow_reports()
    rep = next((r for r in reports if r["id"] == rid), None)
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    vault = load_vault()
    # Pick SNOW vault entry
    keywords = ["snow", "servicenow", "service-now", "generali", "iccrea", "credem", "gosp"]
    if rep["entity"]:
        entry = next((e for e in vault if rep["entity"].lower() in e["portal"].lower()), None)
    else:
        entry = None
    if not entry:
        entry = next((e for e in vault if any(k in e["portal"].lower() for k in keywords)), None)
    if not entry and vault:
        entry = vault[0]
    if not entry:
        return {"success": False, "error": "No credentials in vault. Add ServiceNow credentials first."}

    username = entry["username"]
    password = decrypt(entry["password"])
    instance = entry.get("instance","").strip().rstrip("/")
    if not instance:
        return {"success": False, "error": f"No instance URL for '{entry['portal']}'. Edit it in Password Vault."}
    if not instance.startswith("http"):
        instance = "https://" + instance

    fmt_map = {"excel":"excel","xlsx":"excel","pdf":"pdf","csv":"csv","xml":"xml"}
    snow_fmt = fmt_map.get(rep["fmt"], "excel")
    ext_map  = {"excel":".xlsx","pdf":".pdf","csv":".csv","xml":".xml"}
    ext = ext_map.get(snow_fmt, ".xlsx")

    url = (f"{instance}/report_viewer.do"
           f"?jvar_report_id={rep['report_id']}"
           f"&sysparm_media={snow_fmt}"
           f"&sysparm_format={snow_fmt}")

    # Output path
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = rep["name"].replace(" ","_").replace("/","_")
    fname = f"{safe_name}_{ts}{ext}"
    out_dir = rep["output_dir"].strip() if rep["output_dir"] else os.path.join(DATA_DIR, "..", "downloads")
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, fname)

    started = datetime.datetime.now().isoformat()
    print(f"[SNOW-DL] Downloading report '{rep['name']}' ({rep['report_id']}) → {out_path}")

    try:
        import requests as rq
        try:
            import urllib3; urllib3.disable_warnings()
        except: pass
        r = rq.get(url, auth=(username, password),
                   headers={"Accept":"*/*","User-Agent":"PULSE-AutomationHub/1.0"},
                   timeout=60, stream=True, verify=False)

        if r.status_code == 401:
            raise PermissionError("Wrong username or password (401)")
        if r.status_code == 403:
            raise PermissionError("Access denied (403) — check your SNOW role")
        if r.status_code == 404:
            raise FileNotFoundError(f"Report ID '{rep['report_id']}' not found on SNOW")
        if r.status_code != 200:
            raise RuntimeError(f"SNOW returned HTTP {r.status_code}")

        # Detect HTML login page returned instead of file
        ct = r.headers.get("Content-Type","")
        if "text/html" in ct:
            snippet = r.text[:400]
            if any(x in snippet.lower() for x in ["login","sign in","password"]):
                raise PermissionError("SNOW returned a login page — credentials rejected")

        with open(out_path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk: f.write(chunk)

        size_kb = round(os.path.getsize(out_path)/1024, 1)
        print(f"[SNOW-DL] ✓ {fname} ({size_kb} KB)")

        # Update registry
        for entry2 in reports:
            if entry2["id"] == rid:
                entry2["last_run"]    = started
                entry2["last_status"] = "success"
                entry2["last_path"]   = out_path
        save_snow_reports(reports)

        return {"success": True, "path": out_path, "filename": fname, "size_kb": size_kb}

    except ImportError:
        return {"success": False, "error": "requests library not installed. Run: pip install requests"}
    except Exception as e:
        for entry2 in reports:
            if entry2["id"] == rid:
                entry2["last_run"]    = started
                entry2["last_status"] = "failed"
        save_snow_reports(reports)
        return {"success": False, "error": str(e)}

# ── Apps (Streamlit / External) ───────────────────────────────────────────────
def load_st_apps():
    if not os.path.exists(ST_APPS_FILE): return []
    try:
        with open(ST_APPS_FILE) as f:
            data = f.read().strip()
            return json.loads(data) if data else []
    except: return []

@app.get("/api/st-apps")
def get_st_apps():
    return load_st_apps()

@app.post("/api/st-apps")
async def save_st_apps_endpoint(request: Request):
    apps = await request.json()
    if not isinstance(apps, list):
        raise HTTPException(status_code=400, detail="Expected a list")
    with open(ST_APPS_FILE, "w") as f:
        json.dump(apps, f, indent=2)
    return {"success": True, "count": len(apps)}

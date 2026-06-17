import json, os, sys, hashlib
import jwt
import psycopg2
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from mangum import Mangum
from google.cloud import bigquery
from google.oauth2 import service_account
from pydantic import BaseModel
from typing import List, Optional

# ── CONFIG ──────────────────────────────────────────────────
NEON_URL   = os.environ.get("NEON_DATABASE_URL", "")
BQ_PROJECT = os.environ.get("BQ_PROJECT", "looker-integrations-402615")
BQ_TABLE   = os.environ.get("BQ_TABLE", "looker-integrations-402615.tiktok_ads.conjunto mesclado 3")
SECRET     = os.environ.get("JWT_SECRET", "dev-secret-troque-em-producao")
SA_JSON    = os.environ.get("BQ_SERVICE_ACCOUNT_JSON", "")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"],
    allow_methods=["*"], allow_headers=["*"])

# ── NEONDB ───────────────────────────────────────────────────
def get_db():
    url = NEON_URL
    if not url.endswith("sslmode=require") and "sslmode" not in url:
        url += ("&" if "?" in url else "?") + "sslmode=require"
    return psycopg2.connect(url)

def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id        SERIAL PRIMARY KEY,
            username  TEXT UNIQUE NOT NULL,
            password  TEXT NOT NULL,
            role      TEXT NOT NULL DEFAULT 'client',
            client    TEXT,
            campaigns TEXT[] DEFAULT '{}'
        )
    """)
    cur.execute("""
        INSERT INTO users (username, password, role, client, campaigns)
        VALUES (%s, %s, 'admin', 'inflr Admin', '{}')
        ON CONFLICT (username) DO NOTHING
    """, ('admin', _hash('admin123')))
    conn.commit(); cur.close(); conn.close()

def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()

# ── JWT ──────────────────────────────────────────────────────
def make_token(user):
    return jwt.encode({
        "sub": user["username"], "role": user["role"],
        "client": user["client"], "campaigns": user["campaigns"],
        "exp": datetime.utcnow() + timedelta(hours=12)
    }, SECRET, algorithm="HS256")

def get_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Não autorizado.")
    try:
        return jwt.decode(auth[7:], SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Sessão expirada.")
    except Exception:
        raise HTTPException(401, "Token inválido.")

# ── BIGQUERY ─────────────────────────────────────────────────
def get_bq():
    if SA_JSON:
        info = json.loads(SA_JSON)
        creds = service_account.Credentials.from_service_account_info(info)
        return bigquery.Client(credentials=creds, project=BQ_PROJECT)
    return bigquery.Client(project=BQ_PROJECT)

def camp_filter(user):
    if user["role"] == "admin":
        return "1=1"
    kws = user.get("campaigns", [])
    if not kws:
        return "1=0"
    return "(" + " OR ".join(f"UPPER(CAMPAIGN_NAME) LIKE '%{k.upper()}%'" for k in kws) + ")"

# ── MODELS ───────────────────────────────────────────────────
class LoginBody(BaseModel):
    username: str
    password: str

class UserBody(BaseModel):
    username: str
    password: str
    client: Optional[str] = ""
    campaigns: Optional[List[str]] = []

class DeleteBody(BaseModel):
    username: str

# ── ROTAS AUTH ───────────────────────────────────────────────
@app.post("/api/login")
def login(body: LoginBody):
    try:
        init_db()
    except Exception as e:
        raise HTTPException(500, f"Erro ao inicializar banco: {e}")
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "SELECT username, role, client, campaigns FROM users WHERE username=%s AND password=%s",
        (body.username, _hash(body.password))
    )
    row = cur.fetchone(); cur.close(); conn.close()
    if not row:
        raise HTTPException(401, "Usuário ou senha incorretos.")
    user = {"username": row[0], "role": row[1], "client": row[2], "campaigns": list(row[3] or [])}
    return {**user, "token": make_token(user)}

# ── ROTAS ADMIN ──────────────────────────────────────────────
@app.get("/api/users")
def list_users(user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Acesso negado.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT username, role, client, campaigns FROM users ORDER BY id")
    rows = [{"username":r[0],"role":r[1],"client":r[2],"campaigns":list(r[3] or [])} for r in cur.fetchall()]
    cur.close(); conn.close()
    return rows

@app.post("/api/users")
def create_user(body: UserBody, user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Acesso negado.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (username, password, role, client, campaigns)
        VALUES (%s, %s, 'client', %s, %s)
        ON CONFLICT (username) DO NOTHING RETURNING id
    """, (body.username, _hash(body.password), body.client, body.campaigns))
    ok = cur.fetchone()
    conn.commit(); cur.close(); conn.close()
    if not ok:
        raise HTTPException(400, "Usuário já existe.")
    return {"ok": True}

@app.delete("/api/users")
def delete_user(body: DeleteBody, user=Depends(get_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Acesso negado.")
    if body.username == "admin":
        raise HTTPException(400, "Não é possível remover o admin.")
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=%s", (body.username,))
    conn.commit(); cur.close(); conn.close()
    return {"ok": True}

# ── ROTAS DADOS BIGQUERY ─────────────────────────────────────
@app.get("/api/data")
def get_data(start_date: str, end_date: str, type: str = "kpi", user=Depends(get_user)):
    cf = camp_filter(user)
    tbl = f"`{BQ_TABLE}`"
    bq = get_bq()

    if type == "kpi":
        q = f"""
        SELECT
            SUM(COALESCE(IMPRESSIONS,0))   AS impressions,
            SUM(COALESCE(CLICKS,0))        AS clicks,
            SUM(COALESCE(CLICKS_LINK,0))   AS clicks_link,
            SUM(COALESCE(THRUPLAY,0))      AS thruplay,
            SUM(COALESCE(VIEWS6,0))        AS views6,
            SUM(COALESCE(VIEWS25,0))       AS views25,
            SUM(COALESCE(VIEWS50,0))       AS views50,
            SUM(COALESCE(VIEWS75,0))       AS views75,
            SUM(COALESCE(VIEWS100,0))      AS views100,
            SUM(COALESCE(total_comments,0))         AS comments,
            SUM(COALESCE(total_reacoes,0))          AS reactions,
            SUM(COALESCE(total_salvamentos,0))      AS saves,
            SUM(COALESCE(total_compartilhamento,0)) AS shares,
            SAFE_DIVIDE(SUM(COALESCE(CLICKS,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS ctr,
            SAFE_DIVIDE(SUM(COALESCE(THRUPLAY,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS vtr
        FROM {tbl}
        WHERE date BETWEEN '{start_date}' AND '{end_date}' AND {cf}
        """
        rows = list(bq.query(q).result())
        return dict(rows[0]) if rows else {}

    elif type == "timeseries":
        q = f"""
        SELECT
            CAST(date AS STRING) AS date,
            SUM(COALESCE(IMPRESSIONS,0))  AS impressions,
            SUM(COALESCE(CLICKS,0))       AS clicks,
            SUM(COALESCE(THRUPLAY,0))     AS thruplay,
            SUM(COALESCE(VIEWS25,0))      AS views25,
            SUM(COALESCE(VIEWS50,0))      AS views50,
            SUM(COALESCE(VIEWS75,0))      AS views75,
            SUM(COALESCE(VIEWS100,0))     AS views100,
            SAFE_DIVIDE(SUM(COALESCE(CLICKS,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS ctr,
            SAFE_DIVIDE(SUM(COALESCE(THRUPLAY,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS vtr
        FROM {tbl}
        WHERE date BETWEEN '{start_date}' AND '{end_date}' AND {cf}
        GROUP BY date ORDER BY date ASC
        """
        return {"rows": [dict(r) for r in bq.query(q).result()]}

    elif type == "by_campaign":
        q = f"""
        SELECT
            platform, CAMPAIGN_NAME,
            SUM(COALESCE(IMPRESSIONS,0))  AS impressions,
            SUM(COALESCE(CLICKS,0))       AS clicks,
            SUM(COALESCE(THRUPLAY,0))     AS thruplay,
            SUM(COALESCE(VIEWS100,0))     AS views100,
            SAFE_DIVIDE(SUM(COALESCE(CLICKS,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS ctr,
            SAFE_DIVIDE(SUM(COALESCE(THRUPLAY,0)), NULLIF(SUM(COALESCE(IMPRESSIONS,0)),0)) * 100 AS vtr
        FROM {tbl}
        WHERE date BETWEEN '{start_date}' AND '{end_date}' AND {cf}
        GROUP BY platform, CAMPAIGN_NAME
        ORDER BY impressions DESC
        """
        return {"rows": [dict(r) for r in bq.query(q).result()]}

    raise HTTPException(400, "Tipo inválido.")

# ── SERVIR FRONTEND ──────────────────────────────────────────
@app.get("/{full_path:path}")
def serve(full_path: str):
    p = os.path.join(os.path.dirname(__file__), "../frontend/public/index.html")
    return FileResponse(p)

# Mangum adapta FastAPI para Vercel (AWS Lambda-style)
handler = Mangum(app, lifespan="off")

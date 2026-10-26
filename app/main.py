"""Mon Stock Central : serveur de licences et de versions pour l'APK Mon Stock.

Version 0.1 : API (licences, activation, vérification, versions, incidents, journal).
Le tableau de bord web vient à l'étape suivante.
"""
import base64
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    func,
    or_,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    joinedload,
    mapped_column,
    relationship,
    sessionmaker,
)

APP_VERSION = "0.1.0"
log = logging.getLogger("mon_stock_central")

# --------------------------------------------------------------------------
# Configuration (variables d'environnement)
# --------------------------------------------------------------------------

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
except OSError:  # pragma: no cover
    pass

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'mon_stock_central.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len("postgres://"):]
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg2://" + DATABASE_URL[len("postgresql://"):]

_secret = os.getenv("SECRET_KEY", "")
if _secret and len(_secret) < 32:
    raise RuntimeError("SECRET_KEY doit contenir au moins 32 caractères.")
if not _secret:
    log.warning("SECRET_KEY absente : les sessions admin seront perdues à chaque redémarrage.")
SECRET_KEY = _secret or secrets.token_urlsafe(48)

ADMIN_TOKEN_MINUTES = int(os.getenv("ADMIN_TOKEN_MINUTES", "60"))
TRUST_PROXY = os.getenv("TRUST_PROXY", "0") == "1"
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "0") == "1"
LOGIN_MAX_FAILS = 5
CLIENT_MAX_FAILS = 30

KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sans I, O, 0, 1


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------
# Signature des licences (Ed25519) : l'APK vérifie le jeton hors connexion
# --------------------------------------------------------------------------


def load_signing_key() -> Ed25519PrivateKey:
    raw = os.getenv("LICENCE_SIGNING_KEY", "").strip()
    path = DATA_DIR / "signing_key.b64"
    if not raw and path.exists():
        raw = path.read_text().strip()
    if raw:
        return Ed25519PrivateKey.from_private_bytes(b64u_decode(raw))
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    try:
        path.write_text(b64u(seed))
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover
        log.warning("Impossible d'enregistrer la clé de signature : elle sera perdue au redémarrage.")
    return key


SIGNING_KEY = load_signing_key()
PUBLIC_KEY_B64 = b64u(
    SIGNING_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
)


def sign_token(payload: dict) -> str:
    body = b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signature = b64u(SIGNING_KEY.sign(body.encode()))
    return f"{body}.{signature}"


# --------------------------------------------------------------------------
# Base de données
# --------------------------------------------------------------------------

_engine_args = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {"pool_pre_ping": True}
engine = create_engine(DATABASE_URL, **_engine_args)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class AdminUser(Base):
    __tablename__ = "admin_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Licence(Base):
    __tablename__ = "licences"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    client_name: Mapped[str] = mapped_column(String(200))
    edition: Mapped[str] = mapped_column(String(20), default="standard")
    status: Mapped[str] = mapped_column(String(20), default="pending")
    max_installations: Mapped[int] = mapped_column(Integer, default=1)
    grace_days: Mapped[int] = mapped_column(Integer, default=7)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    installations: Mapped[list["Installation"]] = relationship(back_populates="licence")


class Installation(Base):
    __tablename__ = "installations"
    __table_args__ = (UniqueConstraint("licence_id", "device_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    licence_id: Mapped[int] = mapped_column(ForeignKey("licences.id"), index=True)
    device_id: Mapped[str] = mapped_column(String(64))
    machine_name: Mapped[str] = mapped_column(String(200), default="")
    platform: Mapped[str] = mapped_column(String(20), default="android")
    app_version: Mapped[str] = mapped_column(String(30), default="")
    app_version_code: Mapped[int] = mapped_column(Integer, default=0)
    users_count: Mapped[int] = mapped_column(Integer, default=0)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    licence: Mapped["Licence"] = relationship(back_populates="installations")


class AppVersion(Base):
    __tablename__ = "app_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    version_name: Mapped[str] = mapped_column(String(30))
    version_code: Mapped[int] = mapped_column(Integer, unique=True)
    download_url: Mapped[str] = mapped_column(String(500), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False)
    published: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    licence_id: Mapped[Optional[int]] = mapped_column(ForeignKey("licences.id"), nullable=True)
    installation_id: Mapped[Optional[int]] = mapped_column(ForeignKey("installations.id"), nullable=True)
    severity: Mapped[str] = mapped_column(String(10), default="normal")
    message: Mapped[str] = mapped_column(Text)
    app_version: Mapped[str] = mapped_column(String(30), default="")
    status: Mapped[str] = mapped_column(String(10), default="open")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    licence: Mapped[Optional["Licence"]] = relationship()
    installation: Mapped[Optional["Installation"]] = relationship()


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    actor: Mapped[str] = mapped_column(String(255))
    event: Mapped[str] = mapped_column(String(500))
    result: Mapped[str] = mapped_column(String(20), default="ok")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------
# Outils
# --------------------------------------------------------------------------

ph = PasswordHasher()  # Argon2id
DUMMY_HASH = ph.hash("mot-de-passe-factice")


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.replace(microsecond=0).isoformat() + "Z" if dt else None


def ts(dt: datetime) -> int:
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


def to_naive_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def normalize_key(raw: str) -> str:
    return "".join(raw.upper().split())


def new_key(db: Session) -> str:
    for _ in range(20):
        key = "MS-" + "-".join("".join(secrets.choice(KEY_ALPHABET) for _ in range(4)) for _ in range(3))
        if db.scalar(select(Licence.id).where(Licence.key == key)) is None:
            return key
    raise RuntimeError("Impossible de générer une clé unique.")


def audit(db: Session, actor: str, event: str, result: str = "ok") -> None:
    db.add(AuditLog(actor=actor[:255], event=event[:500], result=result))


def effective_status(lic: Licence, now: datetime) -> str:
    if lic.status in ("pending", "active") and lic.expires_at and lic.expires_at <= now:
        return "expired"
    return lic.status


class Limiter:
    """Limite les essais ratés par adresse IP (en mémoire)."""

    def __init__(self) -> None:
        self.fails: dict = {}

    def _recent(self, ip: str, scope: str, window: int = 900) -> list:
        now = time.time()
        recent = [t for t in self.fails.get((ip, scope), []) if now - t < window]
        self.fails[(ip, scope)] = recent
        return recent

    def check(self, ip: str, scope: str, limit: int) -> None:
        if len(self._recent(ip, scope)) >= limit:
            raise HTTPException(429, {"code": "trop_d_essais", "message": "Trop d'essais. Réessayez dans quelques minutes."})

    def fail(self, ip: str, scope: str) -> None:
        self._recent(ip, scope).append(time.time())

    def reset(self, ip: str, scope: str) -> None:
        self.fails.pop((ip, scope), None)


limiter = Limiter()


def client_ip(request: Request) -> str:
    if TRUST_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "inconnu"


# --------------------------------------------------------------------------
# Schémas de requête
# --------------------------------------------------------------------------


class LoginIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=200)


class LicenceIn(BaseModel):
    client_name: str = Field(min_length=1, max_length=200)
    edition: Literal["standard", "premium"] = "standard"
    max_installations: int = Field(1, ge=1, le=1000)
    grace_days: int = Field(7, ge=0, le=90)
    expires_at: Optional[datetime] = None
    notes: str = Field("", max_length=2000)


class LicencePatch(BaseModel):
    client_name: Optional[str] = Field(None, min_length=1, max_length=200)
    edition: Optional[Literal["standard", "premium"]] = None
    status: Optional[Literal["pending", "active", "suspended", "revoked"]] = None
    max_installations: Optional[int] = Field(None, ge=1, le=1000)
    grace_days: Optional[int] = Field(None, ge=0, le=90)
    expires_at: Optional[datetime] = None
    notes: Optional[str] = Field(None, max_length=2000)


class ClientBase(BaseModel):
    licence_key: str = Field(min_length=5, max_length=64)
    device_id: str = Field(min_length=8, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    app_version: str = Field("", max_length=30)
    app_version_code: int = Field(0, ge=0, le=10_000_000)
    platform: str = Field("android", max_length=20)
    users_count: Optional[int] = Field(None, ge=0, le=100000)


class ActivateIn(ClientBase):
    machine_name: str = Field("", max_length=200)


class CheckIn(ClientBase):
    pass


class IncidentIn(ClientBase):
    severity: Literal["low", "normal", "high"] = "normal"
    message: str = Field(min_length=1, max_length=2000)


def _https_only(value: str) -> str:
    value = value.strip()
    if value and not value.startswith("https://"):
        raise ValueError("L'adresse de téléchargement doit commencer par https://")
    return value


class VersionIn(BaseModel):
    version_name: str = Field(min_length=1, max_length=30)
    version_code: int = Field(ge=1, le=10_000_000)
    download_url: str = Field("", max_length=500)
    notes: str = Field("", max_length=4000)
    mandatory: bool = False
    published: bool = False

    @field_validator("download_url")
    @classmethod
    def check_url(cls, value: str) -> str:
        return _https_only(value)


class VersionPatch(BaseModel):
    version_name: Optional[str] = Field(None, min_length=1, max_length=30)
    download_url: Optional[str] = Field(None, max_length=500)
    notes: Optional[str] = Field(None, max_length=4000)
    mandatory: Optional[bool] = None
    published: Optional[bool] = None

    @field_validator("download_url")
    @classmethod
    def check_url(cls, value: Optional[str]) -> Optional[str]:
        return _https_only(value) if value is not None else None


class IncidentPatch(BaseModel):
    status: Literal["open", "resolved"]


# --------------------------------------------------------------------------
# Sérialisation
# --------------------------------------------------------------------------


def licence_out(lic: Licence) -> dict:
    return {
        "id": lic.id,
        "key": lic.key,
        "client_name": lic.client_name,
        "edition": lic.edition,
        "status": effective_status(lic, utcnow()),
        "max_installations": lic.max_installations,
        "installations": len(lic.installations),
        "grace_days": lic.grace_days,
        "expires_at": iso(lic.expires_at),
        "notes": lic.notes,
        "created_at": iso(lic.created_at),
    }


def installation_out(inst: Installation) -> dict:
    return {
        "id": inst.id,
        "licence_id": inst.licence_id,
        "client_name": inst.licence.client_name,
        "licence_key": inst.licence.key,
        "device_id": inst.device_id,
        "machine_name": inst.machine_name,
        "platform": inst.platform,
        "app_version": inst.app_version,
        "app_version_code": inst.app_version_code,
        "users_count": inst.users_count,
        "last_seen_at": iso(inst.last_seen_at),
        "created_at": iso(inst.created_at),
    }


def incident_out(inc: Incident) -> dict:
    return {
        "id": inc.id,
        "severity": inc.severity,
        "message": inc.message,
        "app_version": inc.app_version,
        "status": inc.status,
        "created_at": iso(inc.created_at),
        "licence_id": inc.licence_id,
        "client_name": inc.licence.client_name if inc.licence else None,
        "machine_name": inc.installation.machine_name if inc.installation else None,
    }


def version_out(v: AppVersion) -> dict:
    return {
        "id": v.id,
        "version_name": v.version_name,
        "version_code": v.version_code,
        "download_url": v.download_url,
        "notes": v.notes,
        "mandatory": v.mandatory,
        "published": v.published,
        "created_at": iso(v.created_at),
    }


# --------------------------------------------------------------------------
# Versions de l'APK et réponses envoyées à l'application
# --------------------------------------------------------------------------


def update_info(db: Session, current_code: int) -> dict:
    latest = db.scalar(
        select(AppVersion).where(AppVersion.published.is_(True)).order_by(AppVersion.version_code.desc()).limit(1)
    )
    if latest is None or latest.version_code <= current_code:
        return {"available": False}
    return {
        "available": True,
        "version_name": latest.version_name,
        "version_code": latest.version_code,
        "download_url": latest.download_url,
        "notes": latest.notes,
        "mandatory": latest.mandatory,
    }


STATUS_ERRORS = {
    "suspended": ("licence_suspendue", "Cette licence est suspendue. Contactez le support. Vos données sont conservées."),
    "revoked": ("licence_revoquee", "Cette licence a été révoquée. Contactez le support."),
    "expired": ("licence_expiree", "Cette licence a expiré. Renouvelez-la pour continuer."),
}


def find_licence(db: Session, raw_key: str, ip: str) -> Licence:
    limiter.check(ip, "client", CLIENT_MAX_FAILS)
    lic = db.scalar(select(Licence).where(Licence.key == normalize_key(raw_key)))
    if lic is None:
        limiter.fail(ip, "client")
        raise HTTPException(404, {"code": "licence_inconnue", "message": "Clé de licence inconnue."})
    return lic


def ensure_usable(db: Session, lic: Licence) -> None:
    status = effective_status(lic, utcnow())
    if status == "expired" and lic.status != "expired":
        lic.status = "expired"
        db.commit()
    if status in STATUS_ERRORS:
        code, message = STATUS_ERRORS[status]
        raise HTTPException(403, {"code": code, "message": message})


def find_installation(db: Session, licence_id: int, device_id: str) -> Optional[Installation]:
    return db.scalar(
        select(Installation).where(Installation.licence_id == licence_id, Installation.device_id == device_id)
    )


def apply_client_fields(inst: Installation, body: ClientBase, now: datetime) -> None:
    inst.last_seen_at = now
    inst.platform = body.platform or inst.platform
    if body.app_version:
        inst.app_version = body.app_version
    inst.app_version_code = body.app_version_code
    if body.users_count is not None:
        inst.users_count = body.users_count
    machine = getattr(body, "machine_name", "")
    if machine:
        inst.machine_name = machine


def client_payload(db: Session, lic: Licence, inst: Installation) -> dict:
    now = utcnow()
    grace_end = now + timedelta(days=lic.grace_days)
    valid_until = min(grace_end, lic.expires_at) if lic.expires_at else grace_end
    token = sign_token(
        {
            "v": 1,
            "licence_id": lic.id,
            "device_id": inst.device_id,
            "edition": lic.edition,
            "status": "active",
            "issued_at": ts(now),
            "valid_until": ts(valid_until),
            "licence_expires_at": ts(lic.expires_at) if lic.expires_at else None,
        }
    )
    return {
        "status": "active",
        "edition": lic.edition,
        "client_name": lic.client_name,
        "expires_at": iso(lic.expires_at),
        "grace_days": lic.grace_days,
        "server_time": ts(now),
        "valid_until": ts(valid_until),
        "token": token,
        "update": update_info(db, inst.app_version_code),
    }


# --------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------


def seed_admin() -> None:
    email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("ADMIN_PASSWORD", "")
    with SessionLocal() as db:
        any_admin = db.scalar(select(AdminUser.id).limit(1)) is not None
        existing = db.scalar(select(AdminUser).where(AdminUser.email == email)) if email else None
        if existing is not None and os.getenv("ADMIN_RESET", "0") == "1" and password:
            existing.password_hash = ph.hash(password)
            audit(db, "système", f"Mot de passe de {email} réinitialisé")
            db.commit()
        elif not any_admin:
            if not email or not password:
                log.warning("Aucun administrateur : définissez ADMIN_EMAIL et ADMIN_PASSWORD.")
                return
            if len(password) < 12:
                raise RuntimeError("ADMIN_PASSWORD doit contenir au moins 12 caractères.")
            db.add(AdminUser(email=email, password_hash=ph.hash(password)))
            audit(db, "système", f"Administrateur {email} créé")
            db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    seed_admin()
    log.info("Clé publique de signature des licences : %s", PUBLIC_KEY_B64)
    yield


app = FastAPI(
    title="Mon Stock Central",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)


@app.middleware("http")
async def entetes_securite(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ----------------------------- Public --------------------------------------


@app.get("/")
def accueil() -> dict:
    return {"service": "Mon Stock Central", "version": APP_VERSION}


@app.get("/health")
def health() -> dict:
    return {"ok": True, "time": iso(utcnow())}


@app.get("/api/v1/public-key")
def public_key() -> dict:
    return {"algorithm": "ed25519", "public_key": PUBLIC_KEY_B64}


@app.get("/api/v1/apk/latest")
def apk_latest(version_code: int = 0, db: Session = Depends(get_db)) -> dict:
    return update_info(db, version_code)


# ----------------------------- Application (APK) ---------------------------


@app.post("/api/v1/client/activate")
def client_activate(body: ActivateIn, request: Request, db: Session = Depends(get_db)) -> dict:
    ip = client_ip(request)
    lic = find_licence(db, body.licence_key, ip)
    ensure_usable(db, lic)
    actor = f"APK {body.device_id[:8]}"
    now = utcnow()
    inst = find_installation(db, lic.id, body.device_id)
    if inst is None:
        if len(lic.installations) >= lic.max_installations:
            audit(db, actor, f"Activation refusée (limite d'appareils) : {lic.key}", "refusée")
            db.commit()
            raise HTTPException(
                409,
                {
                    "code": "licence_deja_utilisee",
                    "message": "Cette licence est déjà utilisée sur le nombre maximum d'appareils.",
                },
            )
        inst = Installation(licence_id=lic.id, device_id=body.device_id, created_at=now)
        db.add(inst)
        audit(db, actor, f"Nouvelle installation activée : {lic.key} ({lic.client_name})")
    apply_client_fields(inst, body, now)
    if lic.status == "pending":
        lic.status = "active"
        audit(db, actor, f"Licence {lic.key} passée à « active »")
    db.commit()
    return client_payload(db, lic, inst)


@app.post("/api/v1/client/check")
def client_check(body: CheckIn, request: Request, db: Session = Depends(get_db)) -> dict:
    ip = client_ip(request)
    lic = find_licence(db, body.licence_key, ip)
    ensure_usable(db, lic)
    inst = find_installation(db, lic.id, body.device_id)
    if inst is None:
        raise HTTPException(
            404,
            {"code": "installation_inconnue", "message": "Cet appareil n'est pas activé. Activez à nouveau la licence."},
        )
    apply_client_fields(inst, body, utcnow())
    db.commit()
    return client_payload(db, lic, inst)


@app.post("/api/v1/client/incident", status_code=201)
def client_incident(body: IncidentIn, request: Request, db: Session = Depends(get_db)) -> dict:
    lic = find_licence(db, body.licence_key, client_ip(request))
    inst = find_installation(db, lic.id, body.device_id)
    incident = Incident(
        licence_id=lic.id,
        installation_id=inst.id if inst else None,
        severity=body.severity,
        message=body.message,
        app_version=body.app_version,
    )
    db.add(incident)
    db.commit()
    return {"ok": True, "id": incident.id}


# ----------------------------- Administration ------------------------------

bearer = HTTPBearer(auto_error=False)


def current_admin(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer),
    db: Session = Depends(get_db),
) -> AdminUser:
    if creds is None:
        raise HTTPException(401, "Authentification requise.")
    try:
        data = jwt.decode(creds.credentials, SECRET_KEY, algorithms=["HS256"])
        admin = db.get(AdminUser, int(data["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        raise HTTPException(401, "Session invalide ou expirée.")
    if admin is None:
        raise HTTPException(401, "Session invalide ou expirée.")
    return admin


@app.post("/api/v1/admin/login")
def admin_login(body: LoginIn, request: Request, db: Session = Depends(get_db)) -> dict:
    ip = client_ip(request)
    limiter.check(ip, "login", LOGIN_MAX_FAILS)
    email = body.email.strip().lower()
    admin = db.scalar(select(AdminUser).where(AdminUser.email == email))
    ok = False
    try:
        ph.verify(admin.password_hash if admin else DUMMY_HASH, body.password)
        ok = admin is not None
    except (VerificationError, InvalidHashError):
        ok = False
    if not ok:
        limiter.fail(ip, "login")
        audit(db, email, "Connexion administrateur", "refusée")
        db.commit()
        raise HTTPException(401, "Identifiants incorrects.")
    limiter.reset(ip, "login")
    audit(db, email, "Connexion administrateur")
    db.commit()
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {"sub": str(admin.id), "iat": now, "exp": now + timedelta(minutes=ADMIN_TOKEN_MINUTES)},
        SECRET_KEY,
        algorithm="HS256",
    )
    return {"access_token": token, "token_type": "bearer", "expires_in": ADMIN_TOKEN_MINUTES * 60}


router = APIRouter(prefix="/api/v1/admin", dependencies=[Depends(current_admin)])


@router.get("/me")
def admin_me(admin: AdminUser = Depends(current_admin)) -> dict:
    return {"email": admin.email}


@router.get("/stats")
def admin_stats(db: Session = Depends(get_db)) -> dict:
    now = utcnow()
    by_status = {status: count for status, count in db.execute(select(Licence.status, func.count()).group_by(Licence.status))}
    latest = db.scalar(
        select(AppVersion).where(AppVersion.published.is_(True)).order_by(AppVersion.version_code.desc()).limit(1)
    )
    return {
        "licences_total": sum(by_status.values()),
        "licences_by_status": by_status,
        "licences_premium": db.scalar(select(func.count()).select_from(Licence).where(Licence.edition == "premium")),
        "installations_total": db.scalar(select(func.count()).select_from(Installation)),
        "installations_active_7d": db.scalar(
            select(func.count()).select_from(Installation).where(Installation.last_seen_at >= now - timedelta(days=7))
        ),
        "users_estimated": db.scalar(select(func.coalesce(func.sum(Installation.users_count), 0))),
        "incidents_open": db.scalar(select(func.count()).select_from(Incident).where(Incident.status == "open")),
        "incidents_high_open": db.scalar(
            select(func.count()).select_from(Incident).where(Incident.status == "open", Incident.severity == "high")
        ),
        "latest_published_version": version_out(latest) if latest else None,
    }


@router.get("/licences")
def list_licences(q: str = "", status: str = "", db: Session = Depends(get_db)) -> list:
    stmt = select(Licence).order_by(Licence.id.desc())
    if status:
        stmt = stmt.where(Licence.status == status)
    if q.strip():
        like = f"%{q.strip()}%"
        stmt = stmt.where(or_(Licence.client_name.ilike(like), Licence.key.ilike(like)))
    return [licence_out(lic) for lic in db.scalars(stmt)]


@router.post("/licences", status_code=201)
def create_licence(body: LicenceIn, admin: AdminUser = Depends(current_admin), db: Session = Depends(get_db)) -> dict:
    lic = Licence(
        key=new_key(db),
        client_name=body.client_name.strip(),
        edition=body.edition,
        max_installations=body.max_installations,
        grace_days=body.grace_days,
        expires_at=to_naive_utc(body.expires_at),
        notes=body.notes,
    )
    db.add(lic)
    audit(db, admin.email, f"Licence créée : {lic.key} ({lic.client_name})")
    db.commit()
    return licence_out(lic)


@router.patch("/licences/{licence_id}")
def update_licence(
    licence_id: int, body: LicencePatch, admin: AdminUser = Depends(current_admin), db: Session = Depends(get_db)
) -> dict:
    lic = db.get(Licence, licence_id)
    if lic is None:
        raise HTTPException(404, "Licence introuvable.")
    data = body.model_dump(exclude_unset=True)
    changes = []
    if "expires_at" in data:
        lic.expires_at = to_naive_utc(data.pop("expires_at"))
        changes.append("expires_at")
    for field, value in data.items():
        if value is not None:
            setattr(lic, field, value)
            changes.append(f"{field}={value}" if field == "status" else field)
    audit(db, admin.email, f"Licence {lic.key} modifiée : {', '.join(changes) or 'aucun changement'}")
    db.commit()
    return licence_out(lic)


@router.get("/installations")
def list_installations(db: Session = Depends(get_db)) -> list:
    stmt = select(Installation).options(joinedload(Installation.licence)).order_by(Installation.last_seen_at.desc())
    return [installation_out(inst) for inst in db.scalars(stmt)]


@router.get("/incidents")
def list_incidents(status: str = "", db: Session = Depends(get_db)) -> list:
    stmt = (
        select(Incident)
        .options(joinedload(Incident.licence), joinedload(Incident.installation))
        .order_by(Incident.id.desc())
        .limit(500)
    )
    if status:
        stmt = stmt.where(Incident.status == status)
    return [incident_out(inc) for inc in db.scalars(stmt)]


@router.patch("/incidents/{incident_id}")
def update_incident(
    incident_id: int, body: IncidentPatch, admin: AdminUser = Depends(current_admin), db: Session = Depends(get_db)
) -> dict:
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(404, "Incident introuvable.")
    inc.status = body.status
    audit(db, admin.email, f"Incident {inc.id} passé à « {body.status} »")
    db.commit()
    return incident_out(inc)


@router.get("/versions")
def list_versions(db: Session = Depends(get_db)) -> list:
    return [version_out(v) for v in db.scalars(select(AppVersion).order_by(AppVersion.version_code.desc()))]


@router.post("/versions", status_code=201)
def create_version(body: VersionIn, admin: AdminUser = Depends(current_admin), db: Session = Depends(get_db)) -> dict:
    if db.scalar(select(AppVersion.id).where(AppVersion.version_code == body.version_code)) is not None:
        raise HTTPException(409, "Ce numéro de version existe déjà.")
    if body.published and not body.download_url:
        raise HTTPException(400, "Ajoutez une adresse de téléchargement avant de publier.")
    version = AppVersion(**body.model_dump())
    db.add(version)
    audit(db, admin.email, f"Version {version.version_name} ({version.version_code}) créée")
    db.commit()
    return version_out(version)


@router.patch("/versions/{version_id}")
def update_version(
    version_id: int, body: VersionPatch, admin: AdminUser = Depends(current_admin), db: Session = Depends(get_db)
) -> dict:
    version = db.get(AppVersion, version_id)
    if version is None:
        raise HTTPException(404, "Version introuvable.")
    for field, value in body.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(version, field, value)
    if version.published and not version.download_url:
        raise HTTPException(400, "Ajoutez une adresse de téléchargement avant de publier.")
    audit(db, admin.email, f"Version {version.version_name} modifiée (publiée : {version.published})")
    db.commit()
    return version_out(version)


@router.get("/audit")
def list_audit(limit: int = 200, db: Session = Depends(get_db)) -> list:
    limit = max(1, min(limit, 1000))
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))
    return [{"id": r.id, "at": iso(r.at), "actor": r.actor, "event": r.event, "result": r.result} for r in rows]


app.include_router(router)

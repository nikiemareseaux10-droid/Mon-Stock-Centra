import os
import tempfile

# Environnement de test : défini AVANT l'import de l'application.
_tmp = tempfile.mkdtemp()
ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "Mot-de-passe-test-123"
os.environ["DATA_DIR"] = _tmp
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["ADMIN_EMAIL"] = ADMIN_EMAIL
os.environ["ADMIN_PASSWORD"] = ADMIN_PASSWORD
os.environ["SECRET_KEY"] = "cle-secrete-de-test-" + "x" * 30

import base64  # noqa: E402
import json  # noqa: E402

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app, limiter  # noqa: E402

DEVICE = "appareil-0001-abcd"


def _pad(text):
    return text + "=" * (-len(text) % 4)


def verify_token(token, public_key_b64):
    """Vérifie la signature comme le fera l'APK, puis renvoie le contenu."""
    body, signature = token.split(".")
    public_key = Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(_pad(public_key_b64)))
    public_key.verify(base64.urlsafe_b64decode(_pad(signature)), body.encode())
    return json.loads(base64.urlsafe_b64decode(_pad(body)))


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client):
    r = client.post("/api/v1/admin/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def new_licence(client, admin, **extra):
    r = client.post("/api/v1/admin/licences", json={"client_name": "Comptoir Test", **extra}, headers=admin)
    assert r.status_code == 201, r.text
    return r.json()


def body_for(key, device=DEVICE, version_code=1):
    return {
        "licence_key": key,
        "device_id": device,
        "machine_name": "Tecno Spark",
        "app_version": "1.0.0",
        "app_version_code": version_code,
    }


def test_sante_et_cle_publique(client):
    assert client.get("/health").json()["ok"] is True
    key = client.get("/api/v1/public-key").json()
    assert key["algorithm"] == "ed25519" and len(key["public_key"]) > 20


def test_admin_protege(client):
    assert client.get("/api/v1/admin/stats").status_code == 401
    assert client.get("/api/v1/admin/licences", headers={"Authorization": "Bearer faux"}).status_code == 401


def test_mauvais_mot_de_passe(client):
    r = client.post("/api/v1/admin/login", json={"email": ADMIN_EMAIL, "password": "mauvais"})
    assert r.status_code == 401
    limiter.fails.clear()


def test_activation_et_jeton_signe(client, admin):
    lic = new_licence(client, admin, edition="premium", grace_days=5)
    assert lic["key"].startswith("MS-") and len(lic["key"]) == 17
    assert lic["status"] == "pending"

    r = client.post("/api/v1/client/activate", json=body_for(lic["key"]))
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "active" and data["edition"] == "premium"

    public_key = client.get("/api/v1/public-key").json()["public_key"]
    payload = verify_token(data["token"], public_key)
    assert payload["device_id"] == DEVICE
    assert payload["valid_until"] - payload["issued_at"] == 5 * 86400

    # Un jeton modifié doit être refusé.
    body, signature = data["token"].split(".")
    faux = base64.urlsafe_b64encode(json.dumps({**payload, "edition": "standard"}).encode()).decode().rstrip("=")
    with pytest.raises(Exception):
        verify_token(faux + "." + signature, public_key)

    # La licence est maintenant active côté administrateur.
    liste = client.get("/api/v1/admin/licences", headers=admin).json()
    cette = next(item for item in liste if item["id"] == lic["id"])
    assert cette["status"] == "active" and cette["installations"] == 1


def test_cle_tolerante_aux_minuscules_et_espaces(client, admin):
    lic = new_licence(client, admin)
    r = client.post("/api/v1/client/activate", json=body_for("  " + lic["key"].lower() + " "))
    assert r.status_code == 200, r.text


def test_cle_inconnue(client):
    r = client.post("/api/v1/client/activate", json=body_for("MS-AAAA-BBBB-CCCC"))
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "licence_inconnue"
    limiter.fails.clear()


def test_limite_d_appareils(client, admin):
    lic = new_licence(client, admin, max_installations=1)
    assert client.post("/api/v1/client/activate", json=body_for(lic["key"])).status_code == 200
    # Le même appareil peut réactiver.
    assert client.post("/api/v1/client/activate", json=body_for(lic["key"])).status_code == 200
    # Un second appareil est refusé.
    r = client.post("/api/v1/client/activate", json=body_for(lic["key"], device="autre-appareil-0002"))
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "licence_deja_utilisee"


def test_suspension_puis_reactivation(client, admin):
    lic = new_licence(client, admin)
    assert client.post("/api/v1/client/activate", json=body_for(lic["key"])).status_code == 200

    r = client.patch(f"/api/v1/admin/licences/{lic['id']}", json={"status": "suspended"}, headers=admin)
    assert r.status_code == 200 and r.json()["status"] == "suspended"
    r = client.post("/api/v1/client/check", json=body_for(lic["key"]))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "licence_suspendue"

    client.patch(f"/api/v1/admin/licences/{lic['id']}", json={"status": "active"}, headers=admin)
    r = client.post("/api/v1/client/check", json=body_for(lic["key"]))
    assert r.status_code == 200 and r.json()["status"] == "active"


def test_revocation(client, admin):
    lic = new_licence(client, admin)
    client.patch(f"/api/v1/admin/licences/{lic['id']}", json={"status": "revoked"}, headers=admin)
    r = client.post("/api/v1/client/activate", json=body_for(lic["key"]))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "licence_revoquee"


def test_licence_expiree(client, admin):
    lic = new_licence(client, admin, expires_at="2020-01-01T00:00:00Z")
    r = client.post("/api/v1/client/activate", json=body_for(lic["key"]))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "licence_expiree"
    liste = client.get("/api/v1/admin/licences", headers=admin).json()
    assert next(item for item in liste if item["id"] == lic["id"])["status"] == "expired"


def test_verification_sans_activation(client, admin):
    lic = new_licence(client, admin)
    r = client.post("/api/v1/client/check", json=body_for(lic["key"]))
    assert r.status_code == 404 and r.json()["detail"]["code"] == "installation_inconnue"


def test_recherche_de_licences(client, admin):
    new_licence(client, admin, client_name="Boutique Zorgho Unique")
    r = client.get("/api/v1/admin/licences", params={"q": "zorgho unique"}, headers=admin)
    assert r.status_code == 200 and len(r.json()) == 1


def test_versions_et_mises_a_jour(client, admin):
    # Aucune version publiée au départ.
    assert client.get("/api/v1/apk/latest", params={"version_code": 1}).json() == {"available": False}

    r = client.post(
        "/api/v1/admin/versions",
        json={"version_name": "1.1.0", "version_code": 10, "notes": "Corrections"},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    version_id = r.json()["id"]
    assert r.json()["published"] is False

    # Doublon refusé.
    r = client.post("/api/v1/admin/versions", json={"version_name": "x", "version_code": 10}, headers=admin)
    assert r.status_code == 409

    # Publication impossible sans adresse de téléchargement.
    r = client.patch(f"/api/v1/admin/versions/{version_id}", json={"published": True}, headers=admin)
    assert r.status_code == 400

    # Adresse non sécurisée refusée.
    r = client.patch(f"/api/v1/admin/versions/{version_id}", json={"download_url": "http://exemple.com/a.apk"}, headers=admin)
    assert r.status_code == 422

    r = client.patch(
        f"/api/v1/admin/versions/{version_id}",
        json={"download_url": "https://exemple.com/mon-stock.apk", "published": True, "mandatory": True},
        headers=admin,
    )
    assert r.status_code == 200, r.text

    latest = client.get("/api/v1/apk/latest", params={"version_code": 1}).json()
    assert latest["available"] is True and latest["version_code"] == 10 and latest["mandatory"] is True
    assert client.get("/api/v1/apk/latest", params={"version_code": 10}).json() == {"available": False}

    # La vérification de licence annonce aussi la mise à jour.
    lic = new_licence(client, admin)
    data = client.post("/api/v1/client/activate", json=body_for(lic["key"], version_code=1)).json()
    assert data["update"]["available"] is True and data["update"]["version_name"] == "1.1.0"


def test_incidents(client, admin):
    lic = new_licence(client, admin)
    client.post("/api/v1/client/activate", json=body_for(lic["key"]))
    r = client.post(
        "/api/v1/client/incident",
        json={**body_for(lic["key"]), "severity": "high", "message": "Impression impossible"},
    )
    assert r.status_code == 201, r.text

    incidents = client.get("/api/v1/admin/incidents", params={"status": "open"}, headers=admin).json()
    trouve = next(i for i in incidents if i["message"] == "Impression impossible")
    assert trouve["severity"] == "high" and trouve["client_name"] == "Comptoir Test"

    r = client.patch(f"/api/v1/admin/incidents/{trouve['id']}", json={"status": "resolved"}, headers=admin)
    assert r.status_code == 200 and r.json()["status"] == "resolved"


def test_statistiques_et_journal(client, admin):
    stats = client.get("/api/v1/admin/stats", headers=admin).json()
    assert stats["licences_total"] >= 1 and stats["installations_total"] >= 1
    assert "licences_by_status" in stats and "incidents_open" in stats

    journal = client.get("/api/v1/admin/audit", headers=admin).json()
    assert len(journal) > 0
    assert any("Licence créée" in ligne["event"] for ligne in journal)


def test_blocage_apres_trop_d_essais_de_connexion(client):
    limiter.fails.clear()
    for _ in range(5):
        r = client.post("/api/v1/admin/login", json={"email": ADMIN_EMAIL, "password": "mauvais"})
        assert r.status_code == 401
    r = client.post("/api/v1/admin/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 429
    limiter.fails.clear()

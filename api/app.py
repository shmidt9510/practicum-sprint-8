import os
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from keycloak import KeycloakOpenID

app = FastAPI()

bearer_scheme = HTTPBearer()

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
KEYCLOAK_ALLOWED_ROLE = os.getenv("KEYCLOAK_ALLOWED_ROLE")

keyclock_credentials = KeycloakOpenID(
    server_url=KEYCLOAK_SERVER_URL,
    realm_name=os.getenv("KEYCLOAK_REALM"),
    client_id=os.getenv("KEYCLOAK_CLIENT_ID")
)

def verify(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    token = credentials.credentials
    try:
        decoded = keyclock_credentials.decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Bad token")
    roles = decoded.get("realm_access", {}).get("roles", [])
    if KEYCLOAK_ALLOWED_ROLE not in roles:
        raise HTTPException(status_code=403, detail="No permissions")

@app.get("/reports")
def get_reports(_=Depends(verify)):
    return "ok"
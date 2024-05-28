import logging

from Crypto import Random
from Crypto.Cipher import AES
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.apache import HtpasswdFile
from pydantic import SecretStr

from .config import settings
from .mpki import (
    Certificate,
    Localisation,
    Partner,
    create_certificate,
    find_certificate_index,
    revoke_certificate,
)

_logger = logging.getLogger(__name__)


# When running the first add "org" the .htpasswd may no exist
try:
    htPass = HtpasswdFile(settings.htpasswd_path)
except FileNotFoundError:
    _logger.error("htpasswd is missing, the service can not run properly")
    htPass = None

app = FastAPI()

security = HTTPBasic()


def get_current_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    if htPass.check_password(credentials.username, credentials.password):
        return credentials
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect user or password",
            headers={"WWW-Authenticate": "Basic"},
        )


def get_current_passphrase(
    credentials: HTTPBasicCredentials = Depends(security),
):
    key = get_current_credentials(credentials).password.encode("utf8")
    vals = settings._read_passphrase_crypt()
    if credentials.username in vals:
        passphrase_crypt = vals[credentials.username]
    else:
        raise Exception(f"No authority with the name {credentials.username}")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    passphrase = cipher.decrypt(bytes.fromhex(passphrase_crypt))[len(iv) :]
    return passphrase.decode("utf8")


def get_current_org(credentials: HTTPBasicCredentials = Depends(security)):
    return get_current_credentials(credentials).username


@app.get("/certs/{serial}")
async def get_cert(serial: str, org: str = Depends(get_current_org)):
    certificate = find_certificate_index(org, serial)
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return certificate


@app.post("/certs")
async def create_cert(
    certificate: Certificate,
    partner: Partner,
    location: Localisation,
    org: str = Depends(get_current_org),
    passphrase: SecretStr = Depends(get_current_passphrase),
):
    return create_certificate(org, certificate, partner, location, passphrase)


@app.delete("/certs/{serial}")
async def revoke_cert(
    serial: str,
    passphrase: str = Depends(get_current_passphrase),
    org: str = Depends(get_current_org),
):
    certificate = find_certificate_index(org, serial)
    return revoke_certificate(org, certificate, passphrase)

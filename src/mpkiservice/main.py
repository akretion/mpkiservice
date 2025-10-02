import logging

from Crypto import Random
from Crypto.Cipher import AES
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.apache import HtpasswdFile

from .config import settings
from .mpki import (
    Authority,
    Certificate,
    Localisation,
    Partner,
)

_logger = logging.getLogger("uvicorn.error")

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


def get_current_authority(credentials: HTTPBasicCredentials = Depends(security)):
    org = get_current_credentials(credentials).username
    return Authority(settings, org)


@app.post("/certs")
async def create_cert(
    certificate: Certificate,
    partner: Partner,
    location: Localisation,
    authority: Authority = Depends(get_current_authority),
    passphrase: str = Depends(get_current_passphrase),
):
    return authority.create_certificate(certificate, partner, location, passphrase)


@app.delete("/certs/{serial}")
async def revoke_cert(
    serial: str,
    authority: Authority = Depends(get_current_authority),
    passphrase: str = Depends(get_current_passphrase),
):
    return authority.revoke_certificate(serial, passphrase)

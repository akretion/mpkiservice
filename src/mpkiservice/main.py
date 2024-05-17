from Crypto import Random
from Crypto.Cipher import AES
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.apache import HtpasswdFile
from pydantic import SecretStr

from config import Settings, get_settings
from mpki import (Certificate, Localisation, Partner, create_certificate,
                  find_certificate_index, revoke_certificate)

htPass = HtpasswdFile(".htpasswd")

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
    settings: Settings = Depends(get_settings),
):
    key = get_current_credentials(credentials).password.encode("utf8")
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    passphrase = cipher.decrypt(bytes.fromhex(settings.PASSPHRASE_CRYPT))[len(iv) :]
    return passphrase.decode("utf8")


def get_current_org(credentials: HTTPBasicCredentials = Depends(security)):
    return get_current_credentials(credentials).username


@app.get("/certs")
async def get_cert(serial: str, org: str = Depends(get_current_org)):
    certificate = find_certificate_index(serial)
    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")
    return certificate


#
# @app.get("/certs/{serial}/download")
# async def download_certificate(serial: str):
#    certificate = get_certificate(serial)
#    if not certificate.path:
#        raise HTTPException(
#            status_code=410, detail="Certificate not downloadable anymore"
#        )
#    return FileResponse(certificate.path)
#


@app.post("/certs")
async def create_cert(
    certificate: Certificate,
    partner: Partner,
    location: Localisation,
    org: str = Depends(get_current_org),
    passphrase: SecretStr = Depends(get_current_passphrase),
):
    return create_certificate(certificate, partner, location, passphrase)


@app.delete("/certs")
async def revoke_cert(serial: str, passphrase: str = Depends(get_current_passphrase)):
    certificate = await get_cert(serial)
    res = revoke_certificate(certificate, passphrase)
    return certificate

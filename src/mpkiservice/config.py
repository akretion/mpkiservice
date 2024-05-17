# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import pathlib
from functools import lru_cache

from pydantic import (BaseModel, BaseSettings, DirectoryPath, EmailStr, Field,
                      FilePath, HttpUrl, SecretStr, constr, validator)


class Settings(BaseSettings):
    # EMAIL PARAMETERS
    SMTP_HOST: str
    SMTP_PORT: int
    SMTP_USER: str
    SMTP_PASSWORD: SecretStr  # = Field(None, env="SMTP_PASSWORD") #TODO: FIXUP
    EMAIL_FROM: EmailStr
    EMAIL_CC: EmailStr = None
    EMAIL_SUBJECT: str

    # SMS PARAMETERS
    SMS_URL: HttpUrl
    SMS_ACCOUNT: str
    SMS_LOGIN: str
    SMS_PASSWORD: SecretStr  # = Field(None, env="SMS_PASSWORD")

    # CERTIFICATE PARAMETERS
    CLIENT_KEY: str = "client.key"
    CLIENT_CSR: str = "client.csr"
    CLIENT_CRT: str = "client.crt"
    CLIENT_P12: str = "client.p12"
    CLIENT_PASS: str = "client.pass"
    CERT_PUBLIC_DIR: DirectoryPath = "./public/certs"
    CERT_BASE_DIR: DirectoryPath = "./ca/certs"
    PKI_DIR: DirectoryPath = "./ca"
    CRL_FILE: pathlib.Path = "./ca/client.crl"  # Created if it does not exist
    CRLNUM_FILE: FilePath = "./ca/crlnumber"  # echo "01" > ca/crlnumber
    INDEX_FILE: FilePath = "./ca/index.txt"
    OPENSSL_CONF: FilePath = "./ca/openssl.cnf"
    PROVIDER_NAME: str = "Akretion"
    CERT_DOWNLOAD_URL: HttpUrl
    PASSPHRASE_CRYPT: str

    class Config:
        env_file = ".env"
        secrets_dir = ".secrets"


@lru_cache()
def get_settings():
    return Settings()

# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
import os
import secrets
import string
from subprocess import run
from typing import Optional, Tuple, Type

import yaml
from Crypto.Random import random
from fastapi import HTTPException
from pydantic import BaseModel, DirectoryPath, EmailStr, HttpUrl, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

logger = logging.getLogger(__name__)


def run_cmd(cmd):
    result = run(cmd, capture_output=True)
    if result.returncode != 0:
        # Becarefull only show the first 4 args as there is no secret in it
        # we should never log secret
        logger.error(f"Fail to launch cmd {cmd[0:4]}. Error : %s" % result.stderr)
        raise HTTPException(status_code=500)


def jpath(*args):
    return os.path.abspath(os.path.join(*args))


def random_string(length):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    password = "".join(secrets.choice(alphabet) for i in range(length))
    return password


class SMTP(BaseModel):
    host: str
    port: int
    user: str
    password: SecretStr
    email_from: EmailStr
    email_cc: Optional[EmailStr] = None
    email_subject: str


class SMS(BaseModel):
    url: HttpUrl
    account: str
    login: str
    password: SecretStr


def randomsecret(length):
    return "".join(
        random.choice(string.ascii_uppercase + string.digits) for i in range(length)
    )


class Settings(BaseSettings):
    smtp: SMTP
    sms: SMS
    cert_public_dir: DirectoryPath = "/var/www/mpki"
    pki_dir: DirectoryPath = "/opt/mpkiservice/ca"
    provider_name: str = "Exemple"
    base_cert_download_url: HttpUrl

    model_config = SettingsConfigDict(
        yaml_file=os.environ.get(
            "MPKISERVICE_CONFIG_PATH", "/opt/mpkiservice/config.yaml"
        )
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (YamlConfigSettingsSource(settings_cls),)

    @property
    def openssl_conf_path(self):
        return jpath(self.pki_dir, "openssl.cnf")

    @property
    def htpasswd_path(self):
        return jpath(self.pki_dir, ".htpasswd")

    @property
    def passphrase_path(self):
        return jpath(self.pki_dir, ".passphrase.yml")

    def _read_passphrase_crypt(self):
        with open(settings.passphrase_path) as f:
            data = f.read()
            vals = yaml.safe_load(data)
            if vals is None:
                vals = {}
        return vals


settings = Settings()

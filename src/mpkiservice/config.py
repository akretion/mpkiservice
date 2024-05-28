# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import logging
import os
import secrets
import string
from subprocess import run
from typing import Tuple, Type

import yaml
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Random import random
from fastapi import HTTPException
from passlib.apache import HtpasswdFile
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
    email_cc: EmailStr = None
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


class Authority:
    CRL_FILE = "client.crl"  # Created if it does not exist
    CRLNUM_FILE = "crlnumber"  # echo "01" > ca/crlnumber
    INDEX_FILE = "index.txt"
    OPENSSL_CONF = "openssl.cnf"

    CERT_BASE_DIR: DirectoryPath = "./ca/certs"

    def __init__(self, settings, name):
        super().__init__()
        self.settings = settings
        self.name = name
        self.dir_path = jpath(self.settings.pki_dir, self.name)

    @property
    def openssl_conf_path(self):
        return jpath(self.dir_path, self.OPENSSL_CONF)

    @property
    def crl_file_path(self):
        return jpath(self.dir_path, self.CRL_FILE)

    def get_cert_path(self, serial):
        return jpath(self.dir_path, "newcerts", f"{serial}.pem")

    @property
    def index_file_path(self):
        return jpath(self.dir_path, self.INDEX_FILE)

    def new_cert(self):
        return Cert(self)

    @property
    def passphrase_crypt(self):
        vals = self._read_passphrase_crypt()
        return vals[self.name]

    def _save_passphrase_crypt(self, passphrase_crypt):
        vals = self.settings._read_passphrase_crypt()
        vals[self.name] = passphrase_crypt
        with open(settings.passphrase_path, "w") as f:
            f.write(yaml.dump(vals))

    def _config_password_and_passphrase(self, password, passphrase):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(password.encode("utf-8"), AES.MODE_CFB, iv)
        passphrase_crypt = iv + cipher.encrypt(passphrase.encode("utf-8"))
        htPass = HtpasswdFile(settings.htpasswd_path)
        htPass.set_password(self.name, password)
        htPass.save()
        self._save_passphrase_crypt(passphrase_crypt.hex())

    def generate_directory(self):
        # Init necessary directory
        for path in [
            self.dir_path,
            jpath(self.dir_path, "private"),
            jpath(self.dir_path, "newcerts"),
        ]:
            if not os.path.exists(path):
                os.makedirs(path)

        # Init needed empty file if missing
        for file_path in [
            settings.passphrase_path,
            settings.htpasswd_path,
            self.index_file_path,
        ]:
            if not os.path.exists(file_path):
                open(file_path, "a").close()

    def generate_openssl_config(self):
        with open(self.openssl_conf_path, "w") as f:
            f.write(
                f"dir = {self.dir_path}\n" f".include {self.settings.openssl_conf_path}"
            )

    def generate_private_key_and_ca(self, password, passphrase, subject):
        self._config_password_and_passphrase(password, passphrase)

        # Generate private key
        pkey_path = jpath(self.dir_path, "private", "cakey.pem")
        careq_path = jpath(self.dir_path, "private", "careq.pem")
        run_cmd(["openssl", "genrsa", "-out", pkey_path, "4096"])

        # Create Request Certificat
        run_cmd(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                pkey_path,
                "-out",
                careq_path,
                "-passin",
                f"pass:{passphrase}",
                "-subj",
                subject,
            ]
        )

        # Create the Certificat Authority
        run_cmd(
            [
                "openssl",
                "ca",
                "-config",
                self.openssl_conf_path,
                "-create_serial",
                "-out",
                jpath(self.dir_path, "cacert.pem"),
                "-days",
                "3650",  # TODO maybe make it configurable
                "-batch",
                "-key",
                passphrase,
                "-keyfile",
                pkey_path,
                "-selfsign",
                "-extensions",
                "v3_ca",
                "-infiles",
                careq_path,
            ]
        )


class Cert:
    def __init__(self, authority):
        super().__init__()
        self.token = random_string(20)
        self.dir_path = os.path.join(authority.dir_path, "certs", self.token)

    @property
    def client_key_path(self):
        return jpath(self.dir_path, "client.key")

    @property
    def client_csr_path(self):
        return jpath(self.dir_path, "client.csr")

    @property
    def client_crt_path(self):
        return jpath(self.dir_path, "client.crt")

    @property
    def client_p12_path(self):
        return jpath(self.dir_path, "client.p12")

    @property
    def client_pass_path(self):
        return jpath(self.dir_path, "client.pass")


class Settings(BaseSettings):
    smtp: SMTP
    sms: SMS
    cert_public_dir: DirectoryPath = "/var/www/mpki"
    pki_dir: DirectoryPath = "/opt/mpkiservice/ca"
    provider_name: str = "Akretion"
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

    def authority(self, name):
        return Authority(self, name)

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

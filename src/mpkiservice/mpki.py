# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import datetime
import logging
import os
import re
import secrets
import smtplib
import urllib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from shutil import copyfile
from subprocess import run

import requests
import yaml
from Crypto import Random
from Crypto.Cipher import AES
from fastapi import HTTPException
from passlib.apache import HtpasswdFile
from phonenumbers import (
    NumberParseException,
    PhoneNumberFormat,
    format_number,
    is_valid_number,
)
from phonenumbers import parse as parse_phone_number
from pydantic import (
    BaseModel,
    DirectoryPath,
    EmailStr,
    HttpUrl,
    SecretStr,
    constr,
    validator,
)

logger = logging.getLogger(__name__)

EMAIL_BODY_TEXT = """Bonjour {partner.name},

Veuillez trouver ci-dessous le lien pour télécharger le
certificat nécessaire à l'enregistrement de votre équipement:

POSTE {certificate.name}: {cert_url}

Cordialement,

{settings.provider_name}
"""

EMAIL_BODY_HTML = """
<html>
  <head></head>
  <body>
    <p>
       Bonjour {partner.name},<br>
       <br>
       Veuillez trouver ci-dessous le lien pour télécharger le certificat nécessaire
       à l'enregistrement de votre matériel:
       <br>
       <strong>POSTE: {certificate.name}</strong>:
       <a href="{cert_url}">Certificat</a>
       <br>
       Cordialement,<br><br>
       {settings.provider_name}
    </p>
  </body>
</html>
"""

# SMS PARAMETERS
SMS_BODY = """Certificat pour {cert_name}
Mot de passe du certificat : {password}"""


def jpath(*args):
    return os.path.abspath(os.path.join(*args))


class Partner(BaseModel):
    name: str
    email: EmailStr
    phone: constr(max_length=25, strip_whitespace=True)

    @validator("phone")
    def check_phone(cls, value):
        try:
            number = parse_phone_number(value)
        except NumberParseException as e:
            raise ValueError("Please provide a valid mobile phone number") from e
        if not is_valid_number(number):
            raise ValueError("Please provide a valid mobile phone number")
        return format_number(number, PhoneNumberFormat.INTERNATIONAL)


class Localisation(BaseModel):
    name: str
    company: str
    city: str
    zipcode: constr(max_length=6, strip_whitespace=True)
    country: str


class Certificate(BaseModel):
    """Schema that represent a certificat in the API"""

    serial: str = None
    valid: bool = True
    name: str
    valid_until: datetime.datetime = None


def random_string(length):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
    password = "".join(secrets.choice(alphabet) for i in range(length))
    return password


FNULL = open(os.devnull, "w")


def sanitize(string):
    return string.replace("/", "?")


def run_cmd(cmd):
    result = run(cmd, capture_output=True)
    if result.returncode != 0:
        # Becarefull only show the first 4 args as there is no secret in it
        # we should never log secret
        logger.error(f"Fail to launch cmd {cmd[0:4]}. Error : %s" % result.stderr)
        raise HTTPException(status_code=500)


class NewCert:
    """Python class that help to generate a new certificat"""

    _p12_filename = "client.p12"

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
        return jpath(self.dir_path, self._p12_filename)

    @property
    def client_pass_path(self):
        return jpath(self.dir_path, "client.pass")


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
        return NewCert(self)

    @property
    def passphrase_crypt(self):
        vals = self._read_passphrase_crypt()
        return vals[self.name]

    def _save_passphrase_crypt(self, passphrase_crypt):
        vals = self.settings._read_passphrase_crypt()
        vals[self.name] = passphrase_crypt
        with open(self.settings.passphrase_path, "w") as f:
            f.write(yaml.dump(vals))

    def _config_password_and_passphrase(self, password, passphrase):
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(password.encode("utf-8"), AES.MODE_CFB, iv)
        passphrase_crypt = iv + cipher.encrypt(passphrase.encode("utf-8"))
        htPass = HtpasswdFile(self.settings.htpasswd_path)
        htPass.set_password(self.name, password)
        htPass.save()
        self._save_passphrase_crypt(passphrase_crypt.hex())

    def generate_directory(self):
        if os.path.exists(self.dir_path):
            raise ValueError(f"Directory {self.dir_path} already exist")

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
            self.settings.passphrase_path,
            self.settings.htpasswd_path,
            self.index_file_path,
        ]:
            if not os.path.exists(file_path):
                open(file_path, "a").close()

        # Create crlnumber file
        with open(jpath(self.dir_path, "crlnumber"), "w") as f:
            f.write("01")

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

    def send_email(self, partner, certificate, cert_url: HttpUrl):
        body_text = EMAIL_BODY_TEXT.format(
            partner=partner,
            certificate=certificate,
            cert_url=cert_url,
            settings=self.settings,
        )
        body_html = EMAIL_BODY_HTML.format(
            partner=partner,
            certificate=certificate,
            cert_url=cert_url,
            settings=self.settings,
        )

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self.settings.smtp.email_subject
            msg["From"] = self.settings.smtp.email_from
            msg["To"] = partner.email
            msg["Cc"] = self.settings.smtp.email_cc or ""
            part1 = MIMEText(body_text, "plain", "utf-8")
            part2 = MIMEText(body_html, "html", "utf-8")
            msg.attach(part1)
            msg.attach(part2)
            server = smtplib.SMTP_SSL(self.settings.smtp.host, self.settings.smtp.port)
            server.ehlo()
            server.login(
                self.settings.smtp.user, self.settings.smtp.password.get_secret_value()
            )
            server.sendmail(
                self.settings.smtp.email_from, partner.email, msg.as_string()
            )
            logger.info(f"email sent to: {partner.email}")
        except Exception as err:
            logger.error(f"email not sent: {err}")

    def send_sms(self, partner, cert_name, password):
        message = SMS_BODY.format(
            cert_name=cert_name[-60:], password=password, settings=self.settings
        )
        try:
            params = {
                "smsAccount": self.settings.sms.account,
                "login": self.settings.sms.login,
                "password": self.settings.sms.password.get_secret_value(),
                "from": self.settings.provider_name.upper(),
                "to": partner.phone,
                "message": message,
                "noStop": 1,
            }
            params = urllib.parse.urlencode(params)
            url = f"{self.settings.sms.url}?{params}"
            requests.get(url)
            logger.info(f"SMS sent to {partner.phone}")
        except Exception as err:
            logger.error(f"SMS not sent to {partner.phone}: {err}")

    def create_certificate(
        self,
        certificate: Certificate,
        partner: Partner,
        location: Localisation,
        passphrase: str,
    ):
        cert = self.new_cert()
        os.makedirs(cert.dir_path, 0o744)

        subject = (
            f"/C=FR/ST={sanitize(location.zipcode)}/O={sanitize(location.company)}"
            f"/OU={sanitize(location.name)}/CN={sanitize(certificate.name)}"
            f"/emailAddress={partner.email}"
        ).encode("ascii", "replace")

        run_cmd(
            [
                "openssl",
                "req",
                "-nodes",
                "-newkey",
                "rsa:4096",
                "-keyout",
                cert.client_key_path,
                "-out",
                cert.client_csr_path,
                "-subj",
                subject,
            ]
        )

        run_cmd(
            [
                "openssl",
                "ca",
                "-batch",
                "-config",
                self.openssl_conf_path,
                "-in",
                cert.client_csr_path,
                "-passin",
                "pass:" + passphrase,
            ]
        )

        certificate = self.find_certificate_index(subject.decode("ascii"))
        src = self.get_cert_path(certificate.serial)
        if not src:
            raise Exception(f"Cert not found ({subject})")
        else:
            copyfile(src, cert.client_crt_path)

        password = random_string(8)
        with os.fdopen(
            os.open(cert.client_pass_path, os.O_WRONLY | os.O_CREAT, 0o700), "w"
        ) as f:
            f.write(password)

        run_cmd(
            [
                "openssl",
                "pkcs12",
                "-export",
                "-out",
                cert.client_p12_path,
                "-inkey",
                cert.client_key_path,
                "-in",
                cert.client_crt_path,
                "-passout",
                f"file:{cert.client_pass_path}",
            ]
        )

        p12_www_file = os.path.join(
            self.settings.cert_public_dir, self.name, cert.token, cert._p12_filename
        )
        os.makedirs(os.path.dirname(p12_www_file), exist_ok=True)
        copyfile(cert.client_p12_path, p12_www_file)
        cert_url = (
            f"{self.settings.cert_public_dir}/{self.name}"
            f"/{cert.token}/{cert._p12_filename}"
        )

        self.send_email(partner, certificate, cert_url)
        self.send_sms(partner, certificate.name, password)
        return certificate

    def find_certificate_index(self, search: str):
        # Search is either subject or serial

        with open(self.index_file_path) as f:
            index_lines = f.readlines()
            certificate = None
            for line in index_lines:
                line = line.strip()
                if not line.startswith("V"):
                    # Only search in valid certificates
                    continue
                if f"\t{search}" in line:
                    columns = re.split("\t", line)
                    if search not in [columns[3], columns[5]]:
                        # Only search in serial and subject columns
                        continue
                    valid_until = datetime.datetime.strptime(
                        columns[1], "%y%m%d%H%M%SZ"
                    )
                    name = (
                        columns[5].split("/CN=")[1].split("/")[0]
                    )  # Substring between /CN= and /
                    certificate = Certificate(
                        serial=columns[3], valid_until=valid_until, name=name
                    )
            if certificate:
                return certificate

    def revoke_certificate(
        self,
        serial: str,
        passphrase: SecretStr,
    ):
        certificate = self.find_certificate_index(serial)
        run_cmd(
            [
                "openssl",
                "ca",
                "-revoke",
                self.get_cert_path(certificate.serial),
                "-config",
                self.openssl_conf_path,
                "-passin",
                "pass:" + passphrase,
            ]
        )
        run_cmd(
            [
                "openssl",
                "ca",
                "-gencrl",
                "-out",
                self.crl_file_path,
                "-config",
                self.openssl_conf_path,
                "-passin",
                "pass:" + passphrase,
            ]
        )

        # set to False so the api response will show valid=False
        certificate.valid = False
        return certificate

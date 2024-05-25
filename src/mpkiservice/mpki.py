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
from fastapi import HTTPException
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

from .config import settings

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


CLIENT_KEY = "client.key"
CLIENT_CSR = "client.csr"
CLIENT_CRT = "client.crt"
CLIENT_P12 = "client.p12"
CLIENT_PASS = "client.pass"
CRL_FILE = "client.crl"  # Created if it does not exist
CRLNUM_FILE = "crlnumber"  # echo "01" > ca/crlnumber
INDEX_FILE = "index.txt"
OPENSSL_CONF = "openssl.cnf"

CERT_BASE_DIR: DirectoryPath = "./ca/certs"


def file_path(authority, filename, absolute=False):
    path = os.path.join(settings.pki_dir, authority.name)
    if absolute:
        return os.path.abspath(path)
    else:
        return path


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
    serial: str = None
    valid: bool = True
    name: str
    valid_until: datetime.datetime = None


def send_email(partner, certificate, cert_url: HttpUrl):
    body_text = EMAIL_BODY_TEXT.format(
        partner=partner, certificate=certificate, cert_url=cert_url, settings=settings
    )
    body_html = EMAIL_BODY_HTML.format(
        partner=partner, certificate=certificate, cert_url=cert_url, settings=settings
    )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = settings.smtp.email_subject
        msg["From"] = settings.smtp.email_from
        msg["To"] = partner.email
        msg["Cc"] = settings.smtp.email_cc or ""
        part1 = MIMEText(body_text, "plain", "utf-8")
        part2 = MIMEText(body_html, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)
        server = smtplib.SMTP_SSL(settings.smtp.host, settings.smtp.port)
        server.ehlo()
        server.login(settings.smtp.user, settings.smtp.password.get_secret_value())
        server.sendmail(settings.smtp.email_from, partner.email, msg.as_string())
        logger.info(f"email sent to: {partner.email}")
    except Exception as err:
        logger.error(f"email not sent: {err}")


def send_sms(partner, cert_name, password):
    message = SMS_BODY.format(
        cert_name=cert_name[-60:], password=password, settings=settings
    )
    try:
        params = {
            "smsAccount": settings.sms.account,
            "login": settings.sms.login,
            "password": settings.sms.password.get_secret_value(),
            "from": settings.provider_name.upper(),
            "to": partner.phone,
            "message": message,
            "noStop": 1,
        }
        params = urllib.parse.urlencode(params)
        url = f"{settings.sms.url}?{params}"
        requests.get(url)
        logger.info(f"SMS sent to {partner.phone}")
    except Exception as err:
        logger.error(f"SMS not sent to {partner.phone}: {err}")


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


def create_certificate(
    org,
    certificate: Certificate,
    partner: Partner,
    location: Localisation,
    passphrase,
):
    token = random_string(20)
    ca_path = os.path.join(settings.pki_dir, org)
    cert_path = os.path.join(ca_path, "certs", token)
    os.makedirs(cert_path, 0o744)

    subject = (
        f"/C=FR/ST={sanitize(location.zipcode)}/O={sanitize(location.company)}"
        f"/OU={sanitize(location.name)}/CN={sanitize(certificate.name)}"
        f"/emailAddress={partner.email}"
    ).encode("ascii", "replace")

    key = os.path.join(cert_path, CLIENT_KEY)
    csr = os.path.join(cert_path, CLIENT_CSR)
    run_cmd(
        [
            "openssl",
            "req",
            "-nodes",
            "-newkey",
            "rsa:4096",
            "-keyout",
            key,
            "-out",
            csr,
            "-subj",
            subject,
        ]
    )

    openssl_conf_path = os.path.abspath(
        os.path.join(settings.pki_dir, org, "openssl.cnf")
    )
    run_cmd(
        [
            "openssl",
            "ca",
            "-batch",
            "-config",
            openssl_conf_path,
            "-in",
            csr,
            "-days",
            "1095",  # 365 * 3 = 3 years TODO: make it configurable
            "-passin",
            "pass:" + passphrase,
        ]
    )

    certificate = find_certificate_index(org, subject.decode("ascii"))
    src = os.path.join(ca_path, "newcerts", f"{certificate.serial}.pem")
    if not src:
        raise Exception(f"Cert not found ({subject})")
    else:
        dst = os.path.join(cert_path, CLIENT_CRT)
        copyfile(src, dst)

    crt_file = os.path.join(cert_path, CLIENT_CRT)
    key_file = os.path.join(cert_path, CLIENT_KEY)
    p12_file = os.path.join(cert_path, CLIENT_P12)
    pass_file = os.path.join(cert_path, CLIENT_PASS)
    password = random_string(8)
    with os.fdopen(os.open(pass_file, os.O_WRONLY | os.O_CREAT, 0o700), "w") as f:
        f.write(password)

    run_cmd(
        [
            "openssl",
            "pkcs12",
            "-export",
            "-out",
            p12_file,
            "-inkey",
            key_file,
            "-in",
            crt_file,
            "-passout",
            f"file:{pass_file}",
        ]
    )

    p12_dir = cert_path.split(os.sep)[-1]
    p12_www_file = os.path.join(settings.cert_public_dir, org, p12_dir, CLIENT_P12)
    os.makedirs(os.path.dirname(p12_www_file), exist_ok=True)
    copyfile(p12_file, p12_www_file)
    cert_url = f"{settings.cert_public_dir}/{org}/{p12_dir}/{CLIENT_P12}"

    send_email(partner, certificate, cert_url)
    send_sms(partner, certificate.name, password)
    return certificate


def find_certificate_index(org, search: str):
    # Search is either subject or serial
    with open(os.path.join(settings.pki_dir, org, INDEX_FILE)) as f:
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
                valid_until = datetime.datetime.strptime(columns[1], "%y%m%d%H%M%SZ")
                name = (
                    columns[5].split("/CN=")[1].split("/")[0]
                )  # Substring between /CN= and /
                certificate = Certificate(
                    serial=columns[3], valid_until=valid_until, name=name
                )
        if certificate:
            return certificate


def revoke_certificate(
    org: str,
    certificate: Certificate,
    passphrase: SecretStr,
):
    src = os.path.join(settings.pki_dir, org, "newcerts", f"{certificate.serial}.pem")
    openssl_conf_path = os.path.abspath(
        os.path.join(settings.pki_dir, org, "openssl.cnf")
    )
    crl_file_path = os.path.abspath(os.path.join(settings.pki_dir, org, CRL_FILE))
    run_cmd(
        [
            "openssl",
            "ca",
            "-revoke",
            os.path.abspath(src),
            "-config",
            openssl_conf_path,
            "-passin",
            "pass:" + passphrase,
        ]
    )
    run_cmd(
        [
            "openssl",
            "ca",
            "-gencrl",
            "-crldays",
            "3650",
            "-out",
            crl_file_path,
            "-config",
            openssl_conf_path,
            "-passin",
            "pass:" + passphrase,
        ]
    )

    # set to False so the api response will show valid=False
    certificate.valid = False
    return certificate

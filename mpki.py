# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import datetime
import logging
import os
import re
import secrets
import smtplib
import subprocess
import urllib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from shutil import copyfile

import requests

from config import Settings, get_settings

logger = logging.getLogger(__name__)

from phonenumbers import (NumberParseException, PhoneNumberFormat,
                          format_number, is_valid_number)
from phonenumbers import parse as parse_phone_number
from pydantic import (BaseModel, BaseSettings, DirectoryPath, EmailStr, Field,
                      FilePath, HttpUrl, SecretStr, constr, validator)

EMAIL_BODY_TEXT = """Bonjour {partner.name},

Veuillez trouver ci-dessous le lien pour télécharger le
certificat nécessaire à l'enregistrement de votre équipement:

POSTE {certificate.name}: {cert_url}

Cordialement,

{settings.PROVIDER_NAME}
"""

EMAIL_BODY_HTML = """
<html>
  <head></head>
  <body>
    <p>
       Bonjour {partner.name},<br>
       <br>
       Veuillez trouver ci-dessous le lien pour télécharger le certificat nécessaire à l'enregistrement de votre matériel:'
    '<br><strong>POSTE: {certificate.name}</strong>: <a href="{cert_url}">Certificat</a>\n'
       <br>
       Cordialement,<br><br>
       {settings.PROVIDER_NAME}
    </p>
  </body>
</html>
"""

# SMS PARAMETERS
SMS_BODY = """Certificat pour {cert_name}
Mot de passe du certificat : {password}"""


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


def send_email(
    partner, certificate, cert_url: HttpUrl, settings: Settings = get_settings()
):

    body_text = EMAIL_BODY_TEXT.format(
        partner=partner, certificate=certificate, cert_url=cert_url, settings=settings
    )
    body_html = EMAIL_BODY_HTML.format(
        partner=partner, certificate=certificate, cert_url=cert_url, settings=settings
    )

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = settings.EMAIL_SUBJECT
        msg["From"] = settings.EMAIL_FROM
        msg["To"] = partner.email
        msg["Cc"] = settings.EMAIL_CC or ""
        part1 = MIMEText(body_text, "plain", "utf-8")
        part2 = MIMEText(body_html, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)
        server = smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT)
        server.ehlo()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD.get_secret_value())
        server.sendmail(settings.EMAIL_FROM, partner.email, msg.as_string())
        logger.info(f"email sent to: {partner.email}")
    except Exception as err:
        logger.error(f"email not sent: {err}")


def send_sms(partner, cert_name, password, settings: Settings = get_settings()):
    message = SMS_BODY.format(
        cert_name=cert_name[-60:], password=password, settings=settings
    )
    try:
        params = {
            "smsAccount": settings.SMS_ACCOUNT,
            "login": settings.SMS_LOGIN,
            "password": settings.SMS_PASSWORD.get_secret_value(),
            "from": settings.PROVIDER_NAME.upper(),
            "to": partner.phone,
            "message": message,
            "noStop": 1,
        }
        params = urllib.parse.urlencode(params)
        url = f"{settings.SMS_URL}?{params}"
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


def create_certificate(
    certificate: Certificate,
    partner: Partner,
    location: Localisation,
    passphrase,
    settings: Settings = get_settings(),
):
    token = random_string(20)
    cert_path = os.path.join(settings.CERT_BASE_DIR, token)
    os.mkdir(cert_path, 0o744)

    subject = f"/C=FR/ST={sanitize(location.zipcode)}/O={sanitize(location.company)}/OU={sanitize(location.name)}/CN={sanitize(certificate.name)}/emailAddress={partner.email}".encode(
        "ascii", "replace"
    )

    key = os.path.join(cert_path, settings.CLIENT_KEY)
    csr = os.path.join(cert_path, settings.CLIENT_CSR)
    args = [
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
    ret = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
    if ret != 0:
        raise subprocess.CalledProcessError(subject, ret)

    args = [
        "openssl",
        "ca",
        "-batch",
        "-config",
        os.path.abspath(settings.OPENSSL_CONF),
        "-in",
        csr,
        "-days",
        "365",
        "-passin",
        "pass:" + passphrase,
    ]
    ret = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
    if ret != 0:
        raise subprocess.CalledProcessError(subject, ret)

    certificate = find_certificate_index(subject.decode("ascii"))
    src = os.path.join(settings.PKI_DIR, "newcerts", f"{certificate.serial}.pem")
    if not src:
        raise Exception("Cert not found (%s)" % subject)
    else:
        dst = os.path.join(cert_path, settings.CLIENT_CRT)
        copyfile(src, dst)

    crt_file = os.path.join(cert_path, settings.CLIENT_CRT)
    key_file = os.path.join(cert_path, settings.CLIENT_KEY)
    p12_file = os.path.join(cert_path, settings.CLIENT_P12)
    pass_file = os.path.join(cert_path, settings.CLIENT_PASS)
    password = random_string(8)
    with os.fdopen(os.open(pass_file, os.O_WRONLY | os.O_CREAT, 0o700), "w") as f:
        f.write(password)

    args = [
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
        "file:%s" % pass_file,
    ]
    ret = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
    if ret != 0:
        raise subprocess.CalledProcessError(subject, ret)

    p12_dir = cert_path.split(os.sep)[-1]
    p12_www_file = os.path.join(settings.CERT_PUBLIC_DIR, p12_dir, settings.CLIENT_P12)
    os.makedirs(os.path.dirname(p12_www_file), exist_ok=True)
    copyfile(p12_file, p12_www_file)
    cert_url = f"{settings.CERT_DOWNLOAD_URL}/{p12_dir}/{settings.CLIENT_P12}"

    send_email(partner, certificate, cert_url)
    send_sms(partner, certificate.name, password)
    return certificate


def find_certificate_index(search: str, settings: Settings = get_settings()):
    # Search is either subject or serial
    with open(settings.INDEX_FILE, "r") as f:
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
    certificate: Certificate, passphrase: SecretStr, settings: Settings = get_settings()
):
    src = os.path.join(settings.PKI_DIR, "newcerts", f"{certificate.serial}.pem")
    args = [
        "openssl",
        "ca",
        "-revoke",
        os.path.abspath(src),
        "-config",
        os.path.abspath(settings.OPENSSL_CONF),
        "-passin",
        "pass:" + passphrase,
    ]
    ret = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
    if ret != 0:
        raise subprocess.CalledProcessError(certificate.serial, ret)
    else:
        certificate.valid = False
    args = [
        "openssl",
        "ca",
        "-gencrl",
        "-crldays",
        "3650",
        "-out",
        os.path.abspath(settings.CRL_FILE),
        "-config",
        os.path.abspath(settings.OPENSSL_CONF),
        "-passin",
        "pass:" + passphrase,
    ]
    ret = subprocess.call(args, stdout=FNULL, stderr=subprocess.STDOUT)
    if ret != 0:
        raise subprocess.CalledProcessError(certificate.serial, ret)
    return certificate

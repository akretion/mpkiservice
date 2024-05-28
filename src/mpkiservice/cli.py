# Copyright 2024 Akretion (https://www.akretion.com).
# @author Sébastien BEAU <sebastien.beau@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).


import typer

from .config import settings

app = typer.Typer(rich_markup_mode="rich")


@app.command()
def add(authority_name: str, password: str, passphrase: str):
    # Create all necessary directory and file
    authority = settings.authority(authority_name)
    authority.generate_directory()
    authority.generate_openssl_config()

    # TODO get subject
    subject = (
        "/countryName=FR/stateOrProvinceName=Rhone Alpes"
        "/organizationName=Akretion/organizationalUnitName=IT"
        "/commonName=Akretion/emailAddress=akretion@example.org/"
    )
    authority.generate_private_key_and_ca(password, passphrase, subject)


@app.command()
def renew(authority_name: str):
    raise NotImplementedError


def main() -> None:
    app()

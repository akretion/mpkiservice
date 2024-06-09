# Copyright 2024 Akretion (https://www.akretion.com).
# @author Sébastien BEAU <sebastien.beau@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).


import typer

from .config import settings
from .mpki import Authority

app = typer.Typer(rich_markup_mode="rich")


@app.command()
def add(
    authority_name: str,
    password: str,
    passphrase: str,
    ca_country_name: str,
    ca_state_or_province_name: str,
    ca_organization_name: str,
    ca_organization_unit_name: str,
    ca_common_name: str,
    ca_email_address: str,
):
    # Create all necessary directory and file
    authority = Authority(settings, authority_name)
    authority.generate_directory()
    authority.generate_openssl_config()
    subject = (
        f"/countryName={ca_country_name}"
        f"/stateOrProvinceName={ca_state_or_province_name}"
        f"/organizationName={ca_organization_name}"
        f"/organizationalUnitName={ca_organization_unit_name}"
        f"/commonName={ca_common_name}"
        f"/emailAddress={ca_email_address}/"
    )
    authority.generate_private_key_and_ca(password, passphrase, subject)


@app.command()
def renew(authority_name: str):
    raise NotImplementedError


def main() -> None:
    app()

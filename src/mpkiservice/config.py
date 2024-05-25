# Copyright 2021 Akretion (https://www.akretion.com).
# @author Pierrick Brun <pierrick.brun@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from typing import Tuple, Type

from pydantic import BaseModel, DirectoryPath, EmailStr, HttpUrl, SecretStr
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)


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


class Authority(BaseModel):
    name: str
    passphrase_crypt: str


class Settings(BaseSettings):
    smtp: SMTP
    sms: SMS
    authorities: list[Authority]
    cert_public_dir: DirectoryPath = "/var/www/mpki"
    pki_dir: DirectoryPath = "./ca"
    provider_name: str = "Akretion"
    base_cert_download_url: HttpUrl

    model_config = SettingsConfigDict(yaml_file="config.yaml")

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


settings = Settings()

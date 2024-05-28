#!/home/sebastien/.local/share/hatch/env/virtual/mpkiservice/0EbWKOZo/mpkiservice/bin/python
# Copyright 2024 Akretion (https://www.akretion.com).
# @author Sébastien BEAU <sebastien.beau@akretion.com>
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

import typer

app = typer.Typer(rich_markup_mode="rich")


@app.command()
def foo(authority_name: str, password: str, passphrase: str):
    import pdb

    pdb.set_trace()


@app.command()
def bar(authority_name: str, password: str, passphrase: str):
    pass


if __name__ == "__main__":
    app()

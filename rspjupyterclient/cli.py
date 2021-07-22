"""RSP Jupyter Client
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

from .client import JupyterClient

import click
import jinja2

CLIENT_PREFIX = "RSPJUPYTERCLIENT_"

# Set up our UI

@click.command()
@click.option(
    "-e",
    "--base-url",
    "--base-url-endpoint",
    envvar=f"{CLIENT_PREFIX}BASE_URL",
    default="http://localhost:8000",
    help="URL of RSP instance to dispatch mobu workers on",
)
@click.option(
    "-j",
    "--json",
    envvar=f"{CLIENT_PREFIX}CONFIG",
    default="./config.json",
    help="JSON document containing client configuration",
)
@click.option(
    "-k",
    "--token",
    "--access-token",
    envvar=["GAFAELFAWR_TOKEN",
            f"{CLIENT_PREFIX}GAFAELFAWR_TOKEN"],
    help= ("Gafaelfawr user token; needs 'exec:notebook' and probably"
           + " 'read:tap' and 'exec:portal' scopes")
)
def main(
    base_url: str,
    json_file: str,
    token: Optional[str],
) -> None:
    """Start an RSP Jupyter client"""
    if not token:
        raise MFError("Admin token must be set")
    with open(json_file,"r") as f:
        config=json.load(f)
    client = JupyterClient(config,base_url,token)
    asyncio.run(client.execute())

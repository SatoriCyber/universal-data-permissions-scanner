"""Console script for authz_analyzer."""
import os
from typing import Optional

import click

from authz_analyzer.main import run_bigquery, run_snowflake
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import OutputFormat


@click.group()
@click.pass_context
@click.option("--debug", is_flag=True, default=False, show_default=True, help="Enable debug logs")
@click.option("--out", required=False, type=str, help="Filename to write output to")
@click.option(
    "--format", required=False, type=click.Choice(["JSON", "CSV"], case_sensitive=False), help="Output format"
)
def main(ctx: click.Context, debug: bool, out: str, _output_format: str):
    """Database Authorization Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['OUT'] = out
    if ctx.obj["format"] == "CSV":
        ctx.obj["FORMAT"] = OutputFormat.Csv
    if ctx.obj["format"] == "JSON":
        ctx.obj["FORMAT"] = OutputFormat.MultiJson
    else:
        raise BaseException("Unknown format")
    # Initializing logger early so we can use it here as needed
    logger = get_logger(debug)
    ctx.obj['LOGGER'] = logger


@main.command()
@click.pass_context
@click.option('--user', required=True, type=str, help="Username")
@click.option('--password', required=True, type=str, help="Password")
@click.option('--account', required=True, type=str, help="Account")
@click.option('--host', required=False, type=str, help="Hostname")
@click.option('--warehouse', required=False, type=str, help="Warehouse")
def snowflake(ctx: click.Context, user: str, password: str, account: str, host: str, warehouse: str):
    """Analyze Snowflake Authorization"""

    run_snowflake(ctx.obj['LOGGER'], user, password, account, host, warehouse, ctx.obj["FORMAT"], ctx.obj['OUT'])


@main.command()
@click.pass_context
@click.option('--project', required=True, type=str, help="GCP project ID, for example: acme-webapp-prod")
@click.option('--key-file', required=False, type=str, help="Path to GCP service account file")
def bigquery(ctx: click.Context, project: str, key_file: Optional[str] = None):
    """Analyze Google BigQuery Authorization"""
    if key_file is not None:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
    run_bigquery(ctx.obj['LOGGER'], project, ctx.obj['FORMAT'], ctx.obj['OUT'])


if __name__ == "__main__":
    main(obj={})

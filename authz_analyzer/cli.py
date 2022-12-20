"""Console script for authz_analyzer."""
import os
import sys
from pathlib import Path
from typing import Optional

import click

if sys.executable != sys.argv[0]:
    sys.path.insert(0, (os.path.join(os.path.dirname(__file__), "..")))


from authz_analyzer.main import run_bigquery, run_postgres, run_s3, run_snowflake
from authz_analyzer.utils.logger import get_logger
from authz_analyzer.writers import OutputFormat


@click.group()
@click.pass_context
@click.option("--debug", '-d', is_flag=True, default=False, show_default=True, help="Enable debug logs")
@click.option("--out", '-o', required=False, type=str, help="Destination output of report", default="authz-analyzer-export.csv")
@click.option(
   "--out-format", '-f', required=False, type=click.Choice(["JSON", "CSV"], case_sensitive=False), help="Output format", default="CSV"
)
def main(ctx: click.Context, debug: bool, out: str, out_format: str):
    """Database Authorization Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['OUT'] = out
    if out_format == "CSV":
        ctx.obj["FORMAT"] = OutputFormat.CSV
    if out_format == "JSON":
        ctx.obj["FORMAT"] = OutputFormat.MULTI_JSON
    else:
        raise BaseException("Unknown format")
    # Initializing logger early so we can use it here as needed
    logger = get_logger(debug)
    ctx.obj['LOGGER'] = logger


@main.command()
@click.pass_context
@click.option('--user', '-u', required=True, type=str, help="Username")
@click.option('--password', '-p', required=True, type=str, help="Password")
@click.option('--account', '-a', required=True, type=str, help="Account")
@click.option('--host', '-t', required=False, type=str, help="Hostname")
@click.option('--warehouse', '-w', required=False, type=str, help="Warehouse")
def snowflake(ctx: click.Context, user: str, password: str, account: str, host: str, warehouse: str):
    """Analyze Snowflake Authorization"""
    output_path = Path(ctx.obj['OUT'])
    run_snowflake(ctx.obj['LOGGER'], user, password, account, host, warehouse, ctx.obj["FORMAT"], output_path)


@main.command()
@click.pass_context
@click.option('--project', '-p',  required=True, type=str, help="GCP project ID, for example: acme-webapp-prod")
@click.option('--key-file', '-k', required=False, type=str, help="Path to GCP service account file")
def bigquery(ctx: click.Context, project: str, key_file: Optional[str] = None):
    """Analyze Google BigQuery Authorization"""
    if key_file is not None:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
    run_bigquery(ctx.obj['LOGGER'], project, ctx.obj['FORMAT'], ctx.obj['OUT'])


@main.command()
@click.pass_context
@click.option('--account-id', required=True, type=str, help="AWS account to analyzed")
@click.option('--account-role-name', required=True, type=str, help="The role to assume in the AWS account")
def s3(ctx: click.Context, account_id, account_role_name):
    run_s3(ctx.obj['LOGGER'], ctx.obj['FORMAT'], ctx.obj['OUT'], account_id, account_role_name)


@main.command()
@click.pass_context
@click.option('--username', '-u', required=True, type=str, help="Postgres username the analyzer should use to connect")
@click.option('--password', '-p', required=True, type=str, help="Postgres password the analyzer should use to connect")
@click.option('--port', required=False, type=str, help="Postgres port", default=5432)
@click.option('--host', '-t', required=True, type=str, help="Postgres host, FQDN or IP")
@click.option('--dbname', '-d', required=False, type=str, help="Postgres database name", default="postgres")
def postgres(ctx: click.Context, username: str, password: str, port: int, host: str, dbname: str):
    """Analyzer Postgres Authorization"""
    run_postgres(logger=ctx.obj['LOGGER'], output_format=ctx.obj['FORMAT'], output_path=ctx.obj['OUT'], username=username, password=password, port=port, host=host, dbname=dbname)


if __name__ == "__main__":
    main(obj={})
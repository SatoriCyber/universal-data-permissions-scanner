"""Console script for authz_analyzer."""
import os
import re
import sys
from pathlib import Path
from typing import List, Optional, TextIO

import click

from universal_data_permissions_scanner.datastores.databricks import (
    Authentication,
)

if sys.executable != sys.argv[0]:
    sys.path.insert(0, (os.path.join(os.path.dirname(__file__), "..")))


from universal_data_permissions_scanner import AwsAssumeRoleInput  # pylint: disable=wrong-import-position
from universal_data_permissions_scanner.main import (  # pylint: disable=wrong-import-position
    run_aws_s3,
    run_bigquery,
    run_mongodb,
    run_mongodb_atlas,
    run_postgres,
    run_redshift,
    run_snowflake,
    run_databricks,
)
from universal_data_permissions_scanner.utils.logger import get_logger  # pylint: disable=wrong-import-position
from universal_data_permissions_scanner.writers import OutputFormat  # pylint: disable=wrong-import-position


@click.group()
@click.pass_context
@click.option("--debug", '-d', is_flag=True, default=False, show_default=True, help="Enable debug logs")
@click.option(
    "--out", '-o', required=False, type=str, help="Destination output of report", default="authz-analyzer-export.csv"
)
@click.option(
    "--out-format",
    '-f',
    required=False,
    type=click.Choice(["JSON", "CSV"], case_sensitive=False),
    help="Output format",
    default="CSV",
)
def main(ctx: click.Context, debug: bool, out: str, out_format: str):
    """Database Authorization Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['OUT'] = out
    if out_format == "CSV":
        ctx.obj["FORMAT"] = OutputFormat.CSV
    elif out_format == "JSON":
        ctx.obj["FORMAT"] = OutputFormat.MULTI_JSON
    else:
        raise Exception("Unknown format")
    # Initializing logger early so we can use it here as needed
    logger = get_logger(debug)
    ctx.obj['LOGGER'] = logger


@main.command()
@click.pass_context
@click.option('--username', '-u', required=True, type=str, help="Username")
@click.option('--password', '-p', required=False, type=str, help="Password")
@click.option('--rsa-key', '-r', required=False, type=click.File('r'), help="Path to RSA private key")
@click.option('--rsa-pass', required=False, type=str, help="RSA key password")
@click.option('--account', '-a', required=True, type=str, help="Account")
@click.option('--host', '-t', required=False, type=str, help="Hostname")
@click.option('--warehouse', '-w', required=False, type=str, help="Warehouse")
def snowflake(
    ctx: click.Context,
    username: str,
    password: Optional[str],
    account: str,
    host: Optional[str],
    warehouse: Optional[str],
    rsa_key: Optional[TextIO],
    rsa_pass: Optional[str],
):
    """Analyze Snowflake Authorization"""
    if not any([password, rsa_key]):
        click.echo('Error: Required at least one of the options: --password / -p or --rsa / -r')
        return

    rsa: Optional[str] = None
    if rsa_key is not None:
        rsa = rsa_key.read()

    output_path = Path(ctx.obj['OUT'])
    kwargs = {}
    if host is not None:
        kwargs['host'] = host
    run_snowflake(
        logger=ctx.obj['LOGGER'],
        username=username,
        password=password,
        account=account,
        warehouse=warehouse,
        output_format=ctx.obj["FORMAT"],
        output_path=output_path,
        rsa_key=rsa,
        rsa_pass=rsa_pass,
        **kwargs,
    )


@main.command()
@click.pass_context
@click.option('--project', '-p', required=True, type=str, help="GCP project ID, for example: acme-webapp-prod")
@click.option('--key-file', '-k', required=False, type=str, help="Path to GCP service account file")
def bigquery(ctx: click.Context, project: str, key_file: Optional[str] = None):
    """Analyze Google BigQuery Authorization"""
    if key_file is not None:
        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = key_file
    run_bigquery(ctx.obj['LOGGER'], project, ctx.obj['FORMAT'], ctx.obj['OUT'])


def valid_multi_aws_account_params(ctx, param, values: Optional[List[str]]) -> Optional[List[AwsAssumeRoleInput]]:
    if not values:
        return None
    return [valid_aws_account_params(ctx, param, value) for value in values]


def valid_aws_account_params(_ctx, _param, value: str) -> AwsAssumeRoleInput:
    # Use regular expression to parse the input string and extract values
    # Valid examples:
    # "role_arn=arn:aws:iam::123456789012:role/role_name"
    # "role_arn=arn:aws:iam::123456789012:role/role_name, external_id: 12345sa43+-@"
    pattern = r"\s*role_arn\s*:\s*([\w/:_\+=,.@\-]+)\s*(,\s*external_id\s*:\s*([\w_\+=,.@\-]+))?\s*$"
    match = re.match(pattern, value)
    if match:
        role_arn = match.group(1)
        if not role_arn:
            raise click.BadParameter("missing 'role_arn'")
        external_id = match.group(3) if match.group(3) else None
        ret = AwsAssumeRoleInput(role_arn=role_arn, external_id=external_id)
        return ret
    raise click.BadParameter("bad format")


@main.command()
@click.pass_context
@click.option(
    '--target-account-params',
    callback=valid_aws_account_params,
    type=str,
    required=True,
    help='AWS target account parameters to analyzed, format: "role_arn: <ROLE_ARN>" format with external id: "role_arn: <ROLE_ARN>, external_id: <EXTERNAL_ID>',
)
@click.option(
    '--additional-account-params',
    callback=valid_multi_aws_account_params,
    required=False,
    default=None,
    multiple=True,
    type=str,
    help='Additional AWS accounts to resolved, format: "role_arn: <ROLE_ARN>" format with external id: "role_arn: <ROLE_ARN>, external_id: <EXTERNAL_ID>',
)
def aws_s3(
    ctx: click.Context,
    target_account_params: AwsAssumeRoleInput,
    additional_account_params: Optional[List[AwsAssumeRoleInput]],
):
    """Analyze AWS S3 buckets"""
    run_aws_s3(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        filename=ctx.obj['OUT'],
        target_account=target_account_params,
        additional_accounts=additional_account_params,
    )


@main.command()
@click.pass_context
@click.option('--username', '-u', required=True, type=str, help="Postgres username the analyzer should use to connect")
@click.option('--password', '-p', required=True, type=str, help="Postgres password the analyzer should use to connect")
@click.option('--port', required=False, type=int, help="Postgres port", default=5432)
@click.option('--host', '-t', required=True, type=str, help="Postgres host, FQDN or IP")
@click.option('--dbname', '-d', required=False, type=str, help="Postgres database name", default="postgres")
def postgres(ctx: click.Context, username: str, password: str, port: int, host: str, dbname: str):
    """Analyze Postgres Authorization"""
    run_postgres(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        output_path=ctx.obj['OUT'],
        username=username,
        password=password,
        port=port,
        host=host,
        dbname=dbname,
    )


@main.command()
@click.pass_context
@click.option('--username', '-u', required=True, type=str, help="Redshift username the analyzer should use to connect")
@click.option('--password', '-p', required=True, type=str, help="Redshift password the analyzer should use to connect")
@click.option('--port', required=False, type=int, help="Redshift port", default=5439)
@click.option('--host', '-t', required=True, type=str, help="Redshift host, FQDN or IP")
@click.option('--dbname', '-d', required=False, type=str, help="Redshift database name", default="dev")
def redshift(ctx: click.Context, username: str, password: str, port: int, host: str, dbname: str):
    """Analyze Redshift Authorization"""
    run_redshift(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        output_path=ctx.obj['OUT'],
        username=username,
        password=password,
        port=port,
        host=host,
        dbname=dbname,
    )


@main.command()
@click.pass_context
@click.option('--username', '-u', required=True, type=str, help="username")
@click.option('--password', '-p', required=True, type=str, help="password")
@click.option('--port', required=False, type=int, help="port", default=27017)
@click.option('--host', '-t', required=True, type=str, help="host, FQDN or IP")
@click.option('--ssl', '-s', required=False, type=bool, help="ssl", default=True)
def mongodb(ctx: click.Context, username: str, password: str, port: int, host: str, ssl: bool):
    """Analyze MongoDB Authorization"""
    run_mongodb(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        output_path=ctx.obj['OUT'],
        username=username,
        password=password,
        port=port,
        host=host,
        ssl=ssl,
    )


@main.command()
@click.pass_context
@click.option('--public_key', '-pk', required=True, type=str, help="Atlas API public key from access manager")
@click.option('--private_key', '-k', required=True, type=str, help="Atlas API private key from access manager")
@click.option(
    '--username',
    '-u',
    required=True,
    type=str,
    help="MongoDB username the analyzer should use to connect to each cluster",
)
@click.option(
    '--password',
    '-p',
    required=True,
    type=str,
    help="MongoDB password the analyzer should use to connect to each cluster",
)
@click.option('--project', '-j', required=True, type=str, help="Atlas project name")
@click.option('--cluster', '-c', required=True, type=str, help="Atlas cluster name")
def atlas(
    ctx: click.Context, public_key: str, private_key: str, username: str, password: str, project: str, cluster: str
):
    """Analyze MongoDB Atlas Authorization"""
    run_mongodb_atlas(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        output_path=ctx.obj['OUT'],
        public_key=public_key,
        private_key=private_key,
        username=username,
        password=password,
        project_name=project,
        cluster_name=cluster,
    )


@main.command()
@click.pass_context
@click.option(
    '--username',
    '-u',
    required=False,
    type=str,
    help="Databricks account admin username",
)
@click.option(
    '--password',
    '-p',
    required=False,
    type=str,
    help="Databricks account admin password",
)
@click.option('--client_id', '-cid', required=False, type=str, help="Client ID for ouath2")
@click.option('--client_secret', '-cis', required=False, type=str, help="Client Secret for ouath2")
@click.option('--tenant_id', '-tid', required=False, type=str, help="Tenant ID for Azure Oauth")
@click.option('--account_id', '-aid', required=True, type=str, help="Databricks Account ID")
@click.option(
    '--host', '-h', required=True, type=str, help="workspace host, e.g. https://<workspace>.cloud.databricks.com"
)
def databricks(
    ctx: click.Context,
    host: str,
    account_id: str,
    username: Optional[str],
    password: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    tenant_id: Optional[str],
):
    """Analyze databricks Authorization"""
    if (username is not None) and (password is not None):
        authentication = Authentication.basic(username=username, password=password)
    elif (client_id is not None) and (client_secret is not None) and (tenant_id is not None):
        authentication = Authentication.oauth_azure(
            client_id=client_id, client_secret=client_secret, tenant_id=tenant_id
        )
    else:
        raise ValueError("Either username and password or client_id, client_secret and tenant_id must be provided")

    run_databricks(
        logger=ctx.obj['LOGGER'],
        output_format=ctx.obj['FORMAT'],
        output_path=ctx.obj['OUT'],
        account_id=account_id,
        host=host,
        authentication=authentication,
    )


if __name__ == "__main__":
    main(obj={})  # pylint: disable=no-value-for-parameter

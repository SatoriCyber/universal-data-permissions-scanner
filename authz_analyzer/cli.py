"""Console script for authz_analyzer."""
import authz_analyzer
import click
import logging
from writers import OutputFormat

@click.group()
@click.pass_context
@click.option("--debug", is_flag=True, default=False, show_default=True, help="Enable debug logs")
@click.option("--out", required=False, type=str, help="Filename to write output to")
@click.option("--format", required=False, type=click.Choice(["JSON", "CSV"], case_sensitive=False), help="Output format")
def main(ctx, debug, out, format):
    """Database Authorization Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['OUT'] = out
    ctx.obj['FORMAT'] = OutputFormat[format.upper() if format else "CSV"]
    # Initializing logger early so we can use it here as needed
    logger = get_logger(debug)
    ctx.obj['LOGGER'] = logger    
    logger.debug("Starting with ctx: %s", ctx.obj)

@main.command()
@click.pass_context
@click.option('--user', required=True, type=str, help="Username")
@click.option('--password', required=True, type=str, help="Password")
@click.option('--account', required=True, type=str, help="Account")
@click.option('--host', required=False, type=str, help="Hostname")
@click.option('--warehouse', required=False, type=str, help="Warehouse")
def snowflake(ctx, user, password, account, host, warehouse):
    """Analyze Snowflake Authorization"""
    authz_analyzer.run_snowflake(user, password, account, host, warehouse)

@main.command()
@click.pass_context
@click.option('--project', required=True, type=str, help="GCP project ID, for example: acme-webapp-prod")
def bigquery(ctx, project: str):
    """Analyze Google BigQuery Authorization"""
    authz_analyzer.run_bigquery(ctx.obj['LOGGER'], project, ctx.obj['FORMAT'], ctx.obj['OUT'])

def get_logger(debug: bool):
    logger = logging.getLogger('authz-analyzer')
    if debug:
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
    return logger

if __name__ == "__main__":
    main(obj={})

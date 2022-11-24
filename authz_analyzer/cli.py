"""Console script for authz_analyzer."""

import authz_analyzer
import click
import logging
from model import OutputFormat

@click.group()
@click.pass_context
@click.option("--debug", is_flag=True, default=False, show_default=True, help="Enable debug logs")
@click.option("--out", required=False, type=str, help="Filename to write output to")
def main(ctx, debug, out):
    """Database Authorization Analyzer"""
    ctx.ensure_object(dict)
    ctx.obj['DEBUG'] = debug
    ctx.obj['OUT'] = out
    ctx.obj['LOGGER'] = get_logger(debug)
    # hard-coded JSON for now, can be controlled by an option later
    ctx.obj['FORMAT'] = OutputFormat.JSON

@main.command()
@click.pass_context
def snowflake(ctx):
    """Analyze Snowflake Authorization"""
    authz_analyzer.run_snowflake()

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

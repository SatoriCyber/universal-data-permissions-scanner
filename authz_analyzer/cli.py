"""Console script for authz_analyzer."""

import click


@click.command()
def main():
    """Main entrypoint."""
    click.echo("authz-analyzer")
    click.echo("=" * len("authz-analyzer"))
    click.echo("Analyze DB authorization")


if __name__ == "__main__":
    main()  # pragma: no cover

"""Main CLI entry point."""

import logging

import typer
from rich.console import Console
from rich.logging import RichHandler

from . import catalog, package

app = typer.Typer(help="Korean Banking Software Analysis Platform")
app.add_typer(package.app, name="package")
app.add_typer(catalog.app, name="catalog")


def setup_logging():
    """Set up Rich logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=Console(), show_path=False)],
    )


def main():
    setup_logging()
    app()


if __name__ == "__main__":
    main()

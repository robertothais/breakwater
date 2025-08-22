from pathlib import Path

import typer

from . import catalog

app = typer.Typer(help="Korean Banking Software Analysis Platform")
app.add_typer(catalog.app, name="catalog")


@app.command()
def download(
    package: str = typer.Argument(..., help="Package name to download sources for"),
):
    """Download all source files for a package."""
    from .download import download_sources

    success = download_sources(package)
    if success:
        typer.echo(f"Downloaded sources for: {package}")
    else:
        typer.echo(f"Failed to download sources for: {package}", err=True)
        raise typer.Exit(1)


@app.command("list")
def list_packages():
    """List all available packages from manifests."""
    manifests_dir = Path("manifests")
    if not manifests_dir.exists():
        typer.echo("Error: No manifests directory found", err=True)
        raise typer.Exit(1)

    yaml_files = list(manifests_dir.glob("*.yaml"))
    if not yaml_files:
        typer.echo("No packages found in manifests/")
        return

    typer.echo("Available packages:")
    for yaml_file in sorted(yaml_files):
        package_name = yaml_file.stem
        typer.echo(f"  - {package_name}")


def main():
    app()


if __name__ == "__main__":
    main()

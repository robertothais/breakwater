import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text
from rich.tree import Tree

from . import catalog
from .package_manager import PackageManager

app = typer.Typer(help="Korean Banking Software Analysis Platform")
app.add_typer(catalog.app, name="catalog")


def setup_logging():
    """Set up Rich logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=Console(), show_path=False)],
    )


def resolve_package_or_exit(
    pm: PackageManager, target: str, architecture: str, checksum: str | None
):
    """Resolve package by checksum or latest version, exit on failure."""
    if checksum:
        package = pm.find_package_by_checksum(target, architecture, checksum)
        if not package:
            typer.echo(
                f"No package found for {target}/{architecture} with checksum {checksum}",
                err=True,
            )
            raise typer.Exit(1)
        return package
    else:
        latest_packages = pm.get_latest_version_download(target, architecture)

        if not latest_packages:
            typer.echo(f"No packages found for {target}/{architecture}", err=True)
            raise typer.Exit(1)
        elif len(latest_packages) > 1:
            typer.echo(
                f"Multiple packages found with same latest version ({latest_packages[0].version}):",
                err=True,
            )
            for p in latest_packages:
                typer.echo(
                    f"  {p.checksum} (downloaded: {p.downloaded_at.strftime('%Y-%m-%d %H:%M:%S')})"
                )
            typer.echo("Use --checksum to specify which one to use.", err=True)
            raise typer.Exit(1)

        return latest_packages[0]


@app.command()
def download(
    target: str = typer.Argument(..., help="Target name to download"),
    architecture: str = typer.Argument(
        ..., help="Architecture (e.g., linux_i386, linux_x64, windows, macos)"
    ),
    overwrite: bool = typer.Option(False, help="Overwrite existing files"),
):
    """Download a package for specified architecture."""
    pm = PackageManager(base_dir=Path.cwd(), overwrite=overwrite)

    result = pm.download_package(target, architecture)

    if not result.was_downloaded:
        console = Console()
        console.print(
            "Package already downloaded. Use --overwrite to overwrite.", style="yellow"
        )
    elif result.was_overwritten:
        console = Console()
        console.print(
            f"Overwriting existing {result.package.download_path.name}", style="red"
        )

    typer.echo(f"Package: {result.package.download_path}")
    if result.package.version:
        typer.echo(f"Version: {result.package.version}")


@app.command("list")
def list_packages():
    """List all available targets and architectures with download status."""
    console = Console()
    pm = PackageManager(base_dir=Path.cwd())
    manifest = pm.load_manifest()

    if not manifest:
        console.print("No targets found in manifest", style="red")
        return

    tree = Tree("Available targets", style="bold blue")

    for target_name, target_info in manifest.items():
        description = target_info.get("description", "")
        target_branch = tree.add(f"{target_name}: {description}", style="bold")

        for arch, arch_info in target_info.items():
            if arch in ["name", "description"]:
                continue

            url = arch_info.get("url", "")

            # Check download status
            packages = pm.list_downloaded_files(target_name)
            arch_packages = [p for p in packages if p.architecture == arch]

            # Check if any package for this architecture is current
            is_current = any(pm.is_package_current(pkg) for pkg in arch_packages)

            # Build architecture line with status
            arch_text = Text(f"{arch}: {url}", style="dim")

            if arch_packages:
                arch_text.append("  ")
                if len(arch_packages) == 1:
                    arch_text.append("[Downloaded]", style="yellow")
                else:
                    arch_text.append(
                        f"[Downloaded ({len(arch_packages)} versions)]", style="yellow"
                    )

                if is_current:
                    arch_text.append("  [Current]", style="red")

            target_branch.add(arch_text)

    console.print(tree)


@app.command()
def unpack(
    target: str = typer.Argument(..., help="Target name to unpack"),
    architecture: str = typer.Argument(
        ..., help="Architecture (e.g., linux_i386, linux_x64, windows, macos)"
    ),
    checksum: str = typer.Option(
        None, help="Exact checksum to specify package (if multiple versions exist)"
    ),
    overwrite: bool = typer.Option(False, help="Overwrite existing unpacked directory"),
):
    """Unpack a downloaded package."""
    pm = PackageManager(base_dir=Path.cwd(), overwrite=overwrite)
    package = resolve_package_or_exit(pm, target, architecture, checksum)
    result = pm.unpack_package(package)

    if not result.was_unpacked:
        console = Console()
        console.print(
            "Package already unpacked. Use --overwrite to overwrite.", style="yellow"
        )
    elif result.was_overwritten:
        console = Console()
        console.print("Overwriting existing unpack", style="red")

    typer.echo(f"Unpacked to: {result.unpack_path}")


@app.command("set-current")
def set_current(
    target: str = typer.Argument(..., help="Target name"),
    architecture: str = typer.Argument(
        ..., help="Architecture (e.g., linux_i386, linux_x64, windows, macos)"
    ),
    checksum: str = typer.Option(
        None, help="Exact checksum to specify package (if multiple versions exist)"
    ),
):
    """Set the current symlink to point to an unpacked package."""
    pm = PackageManager(base_dir=Path.cwd())

    package = resolve_package_or_exit(pm, target, architecture, checksum)

    # Check if the package is unpacked
    if not package.unpack_path.exists():
        typer.echo(
            f"Package not unpacked yet. Run: breakwater unpack {target} {architecture} --checksum {package.checksum}",
            err=True,
        )
        raise typer.Exit(1)

    # Set as current
    pm.set_current(target, package.unpack_path)
    typer.echo(f"Set current -> {package.unpack_path.name}")


def main():
    setup_logging()
    app()


if __name__ == "__main__":
    main()

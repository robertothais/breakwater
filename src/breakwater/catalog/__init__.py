"""Catalog management for Korean banking software analysis."""

import typer
from rich.console import Console
from sqlalchemy import func

from .core import IESite, Package, Service, catalog_session
from .deduplication import get_canonical_name
from .stats import (
    analyze_software_associations,
    analyze_software_distribution,
    calculate_software_usage,
)
from .visualization import (
    create_category_table,
    create_software_usage_table,
    create_stats_table,
    create_usage_distribution_table,
    display_market_basket_analysis,
)

app = typer.Typer(help="Manage the catalog of Korean banking software.")


@app.command()
def update():
    """Download the latest catalog files from the TableClothCatalog repository."""
    typer.echo("Fetching Catalog.xml...")

    from .core import _fetch_catalog_files

    try:
        catalog_xml_content, sites_xml_content = _fetch_catalog_files()
        typer.echo("  Downloaded Catalog.xml")
        typer.echo("  Downloaded sites.xml")
        typer.echo("Catalog files updated successfully.")
    except Exception as e:
        typer.echo(f"Failed to update catalog: {e}", err=True)
        raise typer.Exit(1) from e


@app.command()
def stats(
    all_software: bool = typer.Option(
        False, "--all", help="Show all software packages, not just top 20"
    ),
    market_basket: bool = typer.Option(
        False,
        "--market-basket",
        help="Show market basket analysis (software stacks and associations)",
    ),
):
    """Show statistics about the catalog."""
    console = Console()

    with catalog_session() as session:
        # Get basic counts
        total_services = session.query(Service).count()
        total_packages = session.query(Package).count()
        total_ie_sites = session.query(IESite).count()

        # Overview stats
        stats_table = create_stats_table(total_services, total_packages, total_ie_sites)
        console.print(stats_table)
        console.print()

        # Category breakdown
        category_rows = (
            session.query(Service.category, func.count(Service.id))
            .group_by(Service.category)
            .all()
        )

        category_table = create_category_table(
            [tuple(row) for row in category_rows], total_services
        )
        console.print(category_table)
        console.print()

        # Software usage with deduplication
        services = session.query(Service).all()
        software_usage = calculate_software_usage(services)

        software_table = create_software_usage_table(
            software_usage, total_services, all_software
        )
        console.print(software_table)

        # Usage distribution analysis
        distribution = analyze_software_distribution(software_usage)
        console.print()
        distribution_table = create_usage_distribution_table(distribution)
        console.print(distribution_table)

        # Market basket analysis
        if market_basket:
            try:
                frequent_itemsets, jaccard_rules, kulc_rules = analyze_software_associations(
                    services, min_support=0.01, min_jaccard=0.1
                )
                if not frequent_itemsets.empty and not jaccard_rules.empty:
                    display_market_basket_analysis(frequent_itemsets, jaccard_rules, kulc_rules, total_services, services, console)
                else:
                    console.print(
                        "\nNo significant associations found with current parameters."
                    )
            except ImportError:
                console.print(
                    "\n[red]Market basket analysis requires pandas and mlxtend.[/red]"
                )
                console.print("Install with: pip install pandas mlxtend")


@app.command()
def search(query: str):
    """Search for services by name or URL."""
    with catalog_session() as session:
        # Search in display names and URLs
        services = (
            session.query(Service)
            .filter(
                (Service.display_name.contains(query)) | (Service.url.contains(query))
            )
            .all()
        )

        if services:
            typer.echo(f"\nFound {len(services)} services matching '{query}':")
            for service in services:
                typer.echo(f"\n  ID: {service.id}")
                typer.echo(f"  Name: {service.display_name}")
                typer.echo(f"  Category: {service.category}")
                typer.echo(f"  URL: {service.url}")

                # Show associated packages
                if service.packages:
                    typer.echo("  Packages:")
                    for assoc in service.packages:
                        canonical = get_canonical_name(assoc.package.name)
                        if canonical != assoc.package.name:
                            typer.echo(f"    - {assoc.package.name} → {canonical}")
                        else:
                            typer.echo(f"    - {assoc.package.name}")
        else:
            typer.echo(f"No services found matching '{query}'")

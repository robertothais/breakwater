"""Catalog management for Korean banking software analysis."""

import typer
from rich.console import Console
from sqlalchemy import func
from sqlalchemy.orm import selectinload

from .core import IESite, Package, Service, ServicePackageUrl, catalog_session
from .deduplication import get_canonical_name
from .exporter import export_graph, write_graph_json
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
            frequent_itemsets, jaccard_rules, kulc_rules = (
                analyze_software_associations(
                    services, min_support=0.01, min_jaccard=0.1
                )
            )
            if not frequent_itemsets.empty and not jaccard_rules.empty:
                display_market_basket_analysis(
                    frequent_itemsets,
                    jaccard_rules,
                    kulc_rules,
                    total_services,
                    services,
                    console,
                )
            else:
                console.print(
                    "\nNo significant associations found with current parameters."
                )


@app.command("export-graph")
def export_graph_command(
    out: str = typer.Option(
        "research/explorer/data/graph.json",
        "--out",
        help="Output path for Sigma.js graph JSON",
    ),
    top_n: int = typer.Option(
        60, help="Top-N packages by usage to include in pair metrics"
    ),
    min_joint: int = typer.Option(2, help="Minimum joint count for edges"),
    qmax: float = typer.Option(0.05, help="Max q-value for significance filtering"),
    min_support: float = typer.Option(0.01, help="Min support for frequent itemsets"),
    min_jaccard: float = typer.Option(0.1, help="Min Jaccard for association rules"),
    max_edges: int = typer.Option(2000, help="Maximum number of edges in output"),
    relationships: list[str] = typer.Option(
        ["complementary", "competitive"],
        help="Which edge relationship types to include",
    ),
):
    """Export a Sigma.js graph JSON of package relationships under research/explorer/."""
    console = Console()

    with catalog_session() as session:
        services: list[Service] = (
            session.query(Service)
            .options(
                selectinload(Service.packages).selectinload(ServicePackageUrl.package)
            )
            .all()
        )

    graph = export_graph(
        services,
        top_n=top_n,
        min_joint_count=min_joint,
        min_support=min_support,
        min_jaccard=min_jaccard,
        q_max=qmax,
        relationships=set(relationships),
        max_edges=max_edges,
    )

    write_graph_json(graph, out)
    console.print(f"Wrote graph JSON to [green]{out}[/green]")


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


@app.command("open-explorer")
def open_explorer(
    root: str = typer.Option(
        "research/explorer",
        "--root",
        help="Path to the Sigma.js explorer directory",
    ),
    port: int = typer.Option(8008, "--port", help="Port to serve the explorer"),
    open_browser: bool = typer.Option(
        True, "--open/--no-open", help="Open the default web browser"
    ),
):
    """Serve and open the interactive explorer (Sigma.js)."""
    import os
    import threading
    import webbrowser
    from http.server import SimpleHTTPRequestHandler
    from pathlib import Path
    from socketserver import TCPServer

    console = Console()
    root_path = Path(root).resolve()
    if not root_path.exists():
        raise typer.BadParameter(f"Explorer root not found: {root_path}")

    # Change working directory so static server serves the explorer
    os.chdir(root_path)

    # Try to bind the requested port; if unavailable, raise a clear error
    try:

        class QuietHandler(SimpleHTTPRequestHandler):
            def log_message(self, format, *args):
                pass

        httpd = TCPServer(("127.0.0.1", port), QuietHandler)
    except OSError as e:
        raise typer.Exit(code=1) from e

    url = f"http://127.0.0.1:{port}/"
    console.print(f"Serving explorer from [green]{root_path}[/green] at {url}")
    console.print("Press Ctrl+C to stop.")

    # Serve in background thread
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()

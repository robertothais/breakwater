"""Rich visualization components for catalog statistics and analysis."""

from collections import Counter

import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.text import Text

from .stats import AssociationData, StackData


def create_software_usage_table(
    software_usage: Counter[str], total_services: int, show_all: bool = False
) -> Table:
    title = "All Software Usage" if show_all else "Most Used Software"
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Software", no_wrap=False)
    table.add_column("Services", justify="right")
    table.add_column("Distribution", min_width=30)

    if not software_usage:
        table.add_row("No software found", "", "")
        return table

    sorted_software = (
        software_usage.most_common() if show_all else software_usage.most_common(20)
    )
    max_count = max(software_usage.values()) if software_usage else 1

    for software_name, count in sorted_software:
        filled_width = int((count / max_count) * 20)
        bar = "█" * filled_width + "░" * (20 - filled_width)
        percentage = (count / total_services * 100) if total_services else 0.0
        table.add_row(software_name, str(count), f"{bar} {percentage:.1f}%")

    return table


def create_category_table(
    categories: list[tuple[str | None, int]], total_services: int
) -> Table:
    table = Table(title="Services by Category", show_header=True, header_style="bold")
    table.add_column("Category", no_wrap=False)
    table.add_column("Services", justify="right")
    table.add_column("Distribution", min_width=30)

    if not categories:
        table.add_row("No categories found", "", "")
        return table

    # Category name mapping for display
    category_mapping = {
        "Financing": "Finance",
        "CreditCard": "Credit Card",
    }

    # Sort by count (descending) and apply mapping
    sorted_categories = sorted(
        [(cat, count) for cat, count in categories if cat],
        key=lambda x: x[1],
        reverse=True,
    )
    max_count = max(count for _, count in sorted_categories) if sorted_categories else 1

    for category, count in sorted_categories:
        display_category = category_mapping.get(category, category)
        filled_width = int((count / max_count) * 20)
        bar = "█" * filled_width + "░" * (20 - filled_width)
        percentage = (count / total_services * 100) if total_services else 0.0
        table.add_row(display_category, str(count), f"{bar} {percentage:.1f}%")

    return table


def create_stats_table(
    total_services: int, total_packages: int, total_ie_sites: int
) -> Table:
    table = Table(title="Catalog Overview", show_header=True, header_style="bold")
    table.add_column("Metric", no_wrap=False)
    table.add_column("Count", justify="right")

    table.add_row("Total Services", str(total_services))
    table.add_row("Total Packages", str(total_packages))
    table.add_row("Total IE Sites", str(total_ie_sites))

    return table


def create_stacks_table(stacks: list[StackData], limit: int = 10) -> Table:
    table = Table(title="Common Software Stacks", show_header=True, header_style="bold")
    table.add_column("Stack", no_wrap=False, max_width=35)
    table.add_column("Services", justify="right", width=8)
    table.add_column("Usage", min_width=20)

    if not stacks:
        table.add_row("No stacks found", "", "")
        return table

    max_support = max((stack["support"] for stack in stacks), default=1.0)

    for i, stack in enumerate(stacks[:limit], 1):
        support = stack["support"]
        filled_width = int((support / max_support) * 15)
        bar = "█" * filled_width + "░" * (15 - filled_width)
        support_text = f"{bar} {support * 100:.1f}%"

        packages = stack["packages"]
        
        # First row with stack info
        table.add_row(
            f"[bold]Stack {i}[/bold]",
            f"[bold]{stack['services_count']}[/bold]",
            support_text,
        )
        
        # Package rows (without duplicating stats)
        for pkg in packages:
            table.add_row(
                f"[dim]• {pkg}[/dim]",
                "",  # Empty services column
                "",  # Empty support column
            )
            
        # Add separator row between stacks (except for last stack)
        if i < min(len(stacks), limit):
            table.add_row("", "", "")

    return table


def create_associations_table(
    associations: list[AssociationData], title: str, limit: int = 15
) -> Table:
    table = Table(title=title, show_header=True, header_style="bold")
    table.add_column("Package 1", no_wrap=False)
    table.add_column("Package 2", no_wrap=False)
    table.add_column("Usage", min_width=20)

    if not associations:
        table.add_row("No associations found", "", "")
        return table

    # Scale bars relative to the max in this specific table (not global)
    max_support = max(assoc["support"] for assoc in associations[:limit]) if associations else 1.0
    
    # Use different styling for competitive vs complementary
    is_competitive = "Competitive" in title
    
    for assoc in associations[:limit]:
        # Create support bar visualization scaled to this table's range
        support = assoc["support"]
        filled_width = int((support / max_support) * 15)
        
        # Use same character for all tables
        bar = "█" * filled_width + "░" * (15 - filled_width)
        support_text = f"{bar} {support * 100:.1f}%"

        # Truncate long package names
        pkg1 = (
            assoc["package1"][:25] + "..."
            if len(assoc["package1"]) > 28
            else assoc["package1"]
        )
        pkg2 = (
            assoc["package2"][:25] + "..."
            if len(assoc["package2"]) > 28
            else assoc["package2"]
        )

        table.add_row(pkg1, pkg2, support_text)

    return table


def create_usage_distribution_table(distribution: dict[str, int]) -> Table:
    table = Table(
        title="Software Usage Distribution", show_header=True, header_style="bold"
    )
    table.add_column("Usage Pattern", no_wrap=False)
    table.add_column("Count", justify="right")
    table.add_column("Percentage", justify="right")

    total = distribution["total_software"]
    if total == 0:
        table.add_row("No software found", "", "")
        return table

    patterns = [
        ("Used once only", distribution["used_once"]),
        ("Used 2-5 times", distribution["used_2_to_5"]),
        ("Used more than 5 times", distribution["used_more_than_5"]),
    ]

    for pattern_name, count in patterns:
        percentage = (count / total) * 100 if total > 0 else 0
        table.add_row(pattern_name, str(count), f"{percentage:.1f}%")

    return table


def display_market_basket_analysis(
    frequent_itemsets: pd.DataFrame,
    jaccard_rules: pd.DataFrame,
    kulc_rules: pd.DataFrame,
    total_services: int,
    services: list,
    console: Console | None = None,
) -> None:
    """Display comprehensive market basket analysis results."""
    if console is None:
        console = Console()

    from .stats import (
        find_competitive_packages,
        find_complementary_packages,
        identify_software_stacks,
    )

    # Software stacks
    stacks = identify_software_stacks(
        frequent_itemsets, min_stack_size=3, total_services=total_services
    )
    if stacks:
        console.print()
        stacks_table = create_stacks_table(stacks, limit=10)
        console.print(stacks_table)

    # Complementary packages (using Jaccard)
    complementary = find_complementary_packages(jaccard_rules, min_jaccard=0.3)
    if complementary:
        console.print()
        comp_table = create_associations_table(
            complementary, "Complementary Software (Used Together)", limit=15
        )
        console.print(comp_table)

    # Competitive packages (using support-based analysis)
    competitive = find_competitive_packages(services, min_individual_support=0.05, max_cooccurrence_ratio=0.3)
    if competitive:
        console.print()
        comp_table = create_associations_table(
            competitive, "Competitive Software (Rarely Together)", limit=15
        )
        console.print(comp_table)

"""Statistics and market basket analysis for Korean banking software packages."""

from collections import Counter
from itertools import combinations
from typing import TypedDict

import pandas as pd
from mlxtend.frequent_patterns import apriori, association_rules

from .core import Service
from .deduplication import get_canonical_name


class StackData(TypedDict):
    stack_name: str
    packages: list[str]
    support: float
    services_count: int


class AssociationData(TypedDict):
    package1: str
    package2: str
    lift: float
    confidence: float
    support: float
    relationship: str



def create_service_package_matrix(services: list[Service]) -> pd.DataFrame:
    """Create a binary matrix of services × packages for market basket analysis."""

    # Build the data structure
    data = []
    for service in services:
        service_packages = set()
        for assoc in service.packages:
            canonical = get_canonical_name(assoc.package.name)
            service_packages.add(canonical)

        data.append(
            {
                "service_id": service.id,
                "service_name": service.display_name,
                "packages": service_packages,
            }
        )

    # Get all unique packages
    all_packages = set()
    for row in data:
        all_packages.update(row["packages"])

    # Create binary matrix
    matrix_data = []
    for row in data:
        service_row = {
            "service_id": row["service_id"],
            "service_name": row["service_name"],
        }
        for package in all_packages:
            service_row[package] = package in row["packages"]
        matrix_data.append(service_row)

    return pd.DataFrame(matrix_data)


def analyze_software_associations(
    services: list[Service], min_support: float = 0.02, min_jaccard: float = 0.3
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform market basket analysis to find software associations."""

    # Create binary matrix (services × packages)
    df = create_service_package_matrix(services)

    # Extract only the package columns for apriori
    package_columns = [
        col for col in df.columns if col not in ["service_id", "service_name"]
    ]
    basket_df = df[package_columns]

    # Find frequent itemsets
    frequent_itemsets = apriori(basket_df, min_support=min_support, use_colnames=True)

    if len(frequent_itemsets) == 0:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

    # Generate symmetric associations using Jaccard coefficient
    jaccard_rules = association_rules(
        frequent_itemsets,
        metric="jaccard",
        min_threshold=min_jaccard,
        num_itemsets=len(frequent_itemsets),
    )

    # Generate Kulczynski associations for alternative symmetric metric
    kulc_rules = association_rules(
        frequent_itemsets,
        metric="kulczynski",
        min_threshold=0.5,
        num_itemsets=len(frequent_itemsets),
    )

    return frequent_itemsets, jaccard_rules, kulc_rules


def identify_software_stacks(
    frequent_itemsets: pd.DataFrame, min_stack_size: int = 3, total_services: int = 0
) -> list[StackData]:
    """Identify common software stacks from frequent itemsets."""

    if total_services == 0:
        raise ValueError("total_services parameter is required")

    stacks = []

    for idx, row in frequent_itemsets.iterrows():
        itemset = row["itemsets"]
        support = row["support"]

        if len(itemset) >= min_stack_size:
            stacks.append(
                {
                    "stack_name": f"Stack-{len(stacks) + 1}",
                    "packages": sorted(
                        list(itemset), key=str.lower
                    ),  # Sort alphabetically, case-insensitive
                    "support": support,
                    "services_count": int(support * total_services),
                }
            )

    # Sort by support (most common first)
    return sorted(stacks, key=lambda x: x["support"], reverse=True)


def find_complementary_packages(
    jaccard_rules: pd.DataFrame, min_jaccard: float = 0.3
) -> list[AssociationData]:
    """Find packages that are used together (complementary) using symmetric Jaccard coefficient."""

    complementary = []
    seen_pairs = set()

    for idx, row in jaccard_rules.iterrows():
        # Only include single package -> single package relationships
        if len(row["antecedents"]) == 1 and len(row["consequents"]) == 1:
            pkg1 = list(row["antecedents"])[0]
            pkg2 = list(row["consequents"])[0]

            # Create unordered pair to avoid duplicates
            pair = tuple(sorted([pkg1, pkg2]))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)

            # High Jaccard = complementary (used together frequently)
            if row["jaccard"] >= min_jaccard:
                complementary.append(
                    {
                        "package1": pair[0],
                        "package2": pair[1],
                        "lift": row.get("lift", 0.0),
                        "confidence": row.get("confidence", 0.0),
                        "support": row["support"],
                        "relationship": "complementary",
                    }
                )

    return sorted(complementary, key=lambda x: x["support"], reverse=True)


def find_competitive_packages(
    services: list[Service], min_individual_support: float = 0.05, max_cooccurrence_ratio: float = 0.3
) -> list[AssociationData]:
    """Find packages that are competitive (popular individually but rarely used together)."""
    
    # Calculate individual package usage
    total_services = len(services)
    software_usage = calculate_software_usage(services)
    
    # Get popular packages (above minimum support threshold)
    popular_packages = {
        pkg for pkg, count in software_usage.items() 
        if (count / total_services) >= min_individual_support
    }
    
    competitive = []
    seen_pairs = set()
    
    # Create service-package matrix for popular packages only
    service_packages = {}
    for service in services:
        pkg_set = set()
        for assoc in service.packages:
            canonical = get_canonical_name(assoc.package.name)
            if canonical in popular_packages:
                pkg_set.add(canonical)
        service_packages[service.id] = pkg_set
    
    # Check all pairs of popular packages
    for pkg1, pkg2 in combinations(popular_packages, 2):
        pair = tuple(sorted([pkg1, pkg2]))
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        
        # Count occurrences
        pkg1_count = software_usage[pkg1]
        pkg2_count = software_usage[pkg2]
        both_count = sum(1 for pkg_set in service_packages.values() 
                        if pkg1 in pkg_set and pkg2 in pkg_set)
        
        # Calculate expected co-occurrence if independent
        expected_both = (pkg1_count * pkg2_count) / total_services
        
        # Check if they're competitive (co-occur much less than expected)
        if expected_both > 0:
            cooccurrence_ratio = both_count / expected_both
            joint_support = both_count / total_services
            
            if cooccurrence_ratio <= max_cooccurrence_ratio and joint_support >= 0.01:
                competitive.append({
                    "package1": pair[0],
                    "package2": pair[1],
                    "lift": cooccurrence_ratio,  # Use ratio as proxy for lift
                    "confidence": both_count / min(pkg1_count, pkg2_count),
                    "support": joint_support,
                    "relationship": "competitive",
                })
    
    return sorted(competitive, key=lambda x: x["support"], reverse=True)


def calculate_software_usage(services: list[Service]) -> Counter[str]:
    """Calculate software usage statistics across services with deduplication."""
    software_usage = Counter()

    for service in services:
        seen_canonical = set()  # Track canonical names per service
        for assoc in service.packages:
            canonical_name = get_canonical_name(assoc.package.name)
            if canonical_name not in seen_canonical:
                software_usage[canonical_name] += 1
                seen_canonical.add(canonical_name)

    return software_usage


def analyze_software_distribution(software_usage: Counter[str]) -> dict[str, int]:
    """Analyze the distribution of software usage (single use, few uses, popular)."""
    total_software = len(software_usage)
    used_once = sum(1 for count in software_usage.values() if count == 1)
    used_2_to_5 = sum(1 for count in software_usage.values() if 2 <= count <= 5)
    used_more_than_5 = sum(1 for count in software_usage.values() if count > 5)

    return {
        "total_software": total_software,
        "used_once": used_once,
        "used_2_to_5": used_2_to_5,
        "used_more_than_5": used_more_than_5,
    }



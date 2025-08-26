# %% [markdown]
# Advanced Package Analysis: Coverage and Significance
#
# This notebook (Jupytext .py) demonstrates:
# - Building the service×package matrix
# - Computing pairwise metrics with Fisher's exact test and BH-FDR
# - Running a greedy set cover to find minimal package subsets covering most services
#
# Requirements:
# - pandas, numpy
# - scipy (for Fisher's exact)
# - mlxtend (optional, if you want to compare with apriori metrics)

# %%
from __future__ import annotations

import pandas as pd
from rich.console import Console
from sqlalchemy.orm import selectinload

from breakwater.catalog import (
    Service,
    analyze_software_associations,
    catalog_session,
)
from breakwater.catalog.advanced import (
    add_fisher_fdr,
    compute_pair_metrics,
    greedy_set_cover,
    reconcile_itemsets_with_pairs,
)
from breakwater.catalog.core import ServicePackageUrl
from breakwater.catalog.stats import create_service_package_matrix

console = Console()

# %% [markdown]
# Load catalog data

# %%
with catalog_session() as session:
    # Eager-load relationships to avoid DetachedInstanceError across cells
    services: list[Service] = (
        session.query(Service)
        .options(selectinload(Service.packages).selectinload(ServicePackageUrl.package))
        .all()
    )
    total_services = len(services)
    console.print(f"Loaded services: {total_services}")

# %% [markdown]
# Build service×package matrix (boolean)

# %%
df = create_service_package_matrix(services)
console.print(df.head())

# %% [markdown]
# Compute pairwise metrics (restrict to top-N packages by usage for speed), then add significance (Fisher + BH-FDR)

# %%
pairs = compute_pair_metrics(services, top_n=50, min_joint_count=2)
console.print(f"Pairs computed: {len(pairs)}")

# Require SciPy: fail loudly if unavailable
pairs_sig = add_fisher_fdr(pairs)
# Example filters: significant complementary (lift>1) and competitive (lift<1)
sig_level = 0.05
min_joint = 3
complementary = (
    pairs_sig.query("qvalue <= @sig_level and lift > 1 and a >= @min_joint")
    .sort_values(["qvalue", "lift"], ascending=[True, False])
    .head(30)
)
competitive = (
    pairs_sig.query("qvalue <= @sig_level and lift < 1 and a >= @min_joint")
    .sort_values(["qvalue", "lift"], ascending=[True, True])
    .head(30)
)
console.print("\nTop complementary pairs (significant):")
console.print(complementary[["package1", "package2", "a", "lift", "jaccard", "qvalue"]])

console.print("\nTop competitive pairs (significant):")
console.print(competitive[["package1", "package2", "a", "lift", "jaccard", "qvalue"]])

# %% [markdown]
# Reconcile frequent itemsets with significant pairs to rank robust edges

# %%
try:
    frequent_itemsets, jaccard_rules, kulc_rules = analyze_software_associations(
        services, min_support=0.01, min_jaccard=0.1
    )
    if not frequent_itemsets.empty and "pairs_sig" in locals():
        reconciled = reconcile_itemsets_with_pairs(frequent_itemsets, pairs_sig)
        console.print("\nReconciled edges (top 20):")
        cols = [
            "package1",
            "package2",
            "k_itemsets",
            "max_itemset_support",
            "lift",
            "qvalue",
            "evidence_score",
        ]
        console.print(reconciled[cols].head(20))
    else:
        console.print("[yellow]No frequent itemsets found to reconcile.[/yellow]")
except Exception as e:
    console.print(f"[yellow]Reconciliation skipped:[/yellow] {e}")

# %% [markdown]
# Greedy set cover to reach 80% service coverage

# %%
selections = greedy_set_cover(services, target_coverage=0.8)
sel_df = pd.DataFrame(selections)
console.print("\nGreedy set-cover selections:")
console.print(sel_df)

# %% [markdown]
# Coverage impact curve (optional): compute cumulative coverage vs k

# %%
if not sel_df.empty:
    sel_df["k"] = range(1, len(sel_df) + 1)
    curve = sel_df[["k", "coverage_fraction"]]
    console.print("\nCoverage curve (k vs coverage):")
    console.print(curve)

# %% [markdown]
# Notes:
# - Increase `top_n` for `compute_pair_metrics` for more exhaustive pairs (may be O(N^2)).
# - Adjust `min_joint_count` to suppress very rare pairs.
# - For visualization, consider exporting DataFrames to CSV and plotting in seaborn.

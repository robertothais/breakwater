"""Advanced statistical analyses for package relationships and coverage.

Includes:
- Pairwise metrics with significance testing (Fisher's exact + BH-FDR)
- Greedy set cover to identify minimal package subsets covering most services
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from itertools import combinations

import numpy as np
import pandas as pd

from .core import Service
from .deduplication import get_canonical_name
from .stats import calculate_software_usage


def _build_service_packages(services: list[Service]) -> dict[str, set[str]]:
    """Return service_id -> set of canonical package names for each service."""
    service_packages: dict[str, set[str]] = {}
    for service in services:
        pkg_set: set[str] = set()
        for assoc in service.packages:
            pkg_set.add(get_canonical_name(assoc.package.name))
        service_packages[service.id] = pkg_set
    return service_packages


def _benjamini_hochberg(pvals: Iterable[float]) -> np.ndarray:
    """Benjamini-Hochberg FDR correction.

    Returns array of q-values in the original order of pvals.
    """
    pvals = np.asarray(list(pvals), dtype=float)
    m = len(pvals)
    if m == 0:
        return pvals
    order = np.argsort(pvals)
    ranked = np.empty(m, dtype=float)
    ranked[order] = (pvals[order] * m) / (np.arange(1, m + 1))
    # Enforce monotonicity
    for i in range(m - 2, -1, -1):
        ranked[order[i]] = min(ranked[order[i]], ranked[order[i + 1]])
    return np.minimum(ranked, 1.0)


def compute_pair_metrics(
    services: list[Service],
    top_n: int | None = None,
    min_joint_count: int = 1,
) -> pd.DataFrame:
    """Compute pairwise counts, supports, lift, and jaccard for package pairs.

    - Optionally restrict to top_n packages by individual usage to bound complexity.
    - Filters out pairs with joint count < min_joint_count.
    """
    total_services = len(services)
    if total_services == 0:
        return pd.DataFrame(
            columns=[
                "package1",
                "package2",
                "a",
                "b",
                "c",
                "d",
                "support_a",
                "support_b",
                "support_both",
                "lift",
                "jaccard",
            ]
        )

    service_packages = _build_service_packages(services)
    usage = calculate_software_usage(services)

    packages = list(usage.keys())
    if top_n is not None and top_n > 0:
        packages = [pkg for pkg, _ in usage.most_common(top_n)]

    # Precompute per-package service sets for fast pair counts
    pkg_to_services: dict[str, set[str]] = defaultdict(set)
    for sid, pkgs in service_packages.items():
        for p in pkgs:
            if p in packages:
                pkg_to_services[p].add(sid)

    rows: list[dict] = []
    for p1, p2 in combinations(packages, 2):
        s1 = pkg_to_services.get(p1, set())
        s2 = pkg_to_services.get(p2, set())
        a = len(s1 & s2)  # both
        if a < min_joint_count:
            continue
        b = len(s1 - s2)  # p1 only
        c = len(s2 - s1)  # p2 only
        d = total_services - (a + b + c)  # neither

        support_a = (a + b) / total_services
        support_b = (a + c) / total_services
        support_both = a / total_services
        # Classical lift
        lift = (
            (support_both / (support_a * support_b))
            if support_a > 0 and support_b > 0
            else np.nan
        )
        # Jaccard index
        denom = a + b + c
        jaccard = (a / denom) if denom > 0 else 0.0

        rows.append(
            {
                "package1": p1,
                "package2": p2,
                "a": a,
                "b": b,
                "c": c,
                "d": d,
                "support_a": support_a,
                "support_b": support_b,
                "support_both": support_both,
                "lift": lift,
                "jaccard": jaccard,
            }
        )

    return pd.DataFrame(rows)


def add_fisher_fdr(pairs_df: pd.DataFrame) -> pd.DataFrame:
    """Add Fisher's exact test p-values and BH-FDR q-values to pair metrics.

    Requires SciPy. If unavailable, raises ImportError with guidance.
    """
    if pairs_df.empty:
        pairs_df = pairs_df.copy()
        pairs_df["pvalue"] = []
        pairs_df["qvalue"] = []
        return pairs_df

    try:
        from scipy.stats import fisher_exact  # type: ignore
    except Exception as e:  # pragma: no cover - environment dependent
        raise ImportError(
            "SciPy is required for Fisher's exact test. Install with: pip install scipy"
        ) from e

    pvals: list[float] = []
    for _, row in pairs_df.iterrows():
        a, b, c, d = int(row["a"]), int(row["b"]), int(row["c"]), int(row["d"])
        # Two-sided test for any dependence
        _, p = fisher_exact([[a, b], [c, d]], alternative="two-sided")
        pvals.append(float(p))

    qvals = _benjamini_hochberg(pvals)

    out = pairs_df.copy()
    out["pvalue"] = pvals
    out["qvalue"] = qvals
    return out


def greedy_set_cover(
    services: list[Service],
    target_coverage: float = 0.8,
    max_packages: int | None = None,
    restrict_to: set[str] | None = None,
) -> list[dict]:
    """Greedy set cover over packages to cover services that use them.

    Returns an ordered list of selections with marginal and cumulative coverage.
    """
    assert 0.0 <= target_coverage <= 1.0
    total_services = len(services)
    if total_services == 0:
        return []

    service_packages = _build_service_packages(services)

    # Build package -> service_ids mapping
    pkg_to_services: dict[str, set[str]] = defaultdict(set)
    for sid, pkgs in service_packages.items():
        for p in pkgs:
            if restrict_to is None or p in restrict_to:
                pkg_to_services[p].add(sid)

    covered: set[str] = set()
    available = set(pkg_to_services.keys())
    selections: list[dict] = []

    # Precompute usage for tie-breaking
    usage = calculate_software_usage(services)

    while len(covered) / total_services < target_coverage and available:
        # Pick package with max marginal gain; break ties by usage
        best_pkg = None
        best_gain = -1
        for p in available:
            gain = len(pkg_to_services[p] - covered)
            if gain > best_gain or (
                gain == best_gain
                and usage[p] > (usage.get(best_pkg, -1) if best_pkg else -1)
            ):
                best_pkg = p
                best_gain = gain

        if best_pkg is None or best_gain <= 0:
            break

        newly = pkg_to_services[best_pkg] - covered
        covered |= pkg_to_services[best_pkg]
        available.remove(best_pkg)

        selections.append(
            {
                "package": best_pkg,
                "marginal_services": len(newly),
                "total_covered": len(covered),
                "coverage_fraction": len(covered) / total_services,
            }
        )

        if max_packages is not None and len(selections) >= max_packages:
            break

    return selections


def reconcile_itemsets_with_pairs(
    frequent_itemsets: pd.DataFrame,
    pairs_df: pd.DataFrame,
    min_itemset_size: int = 2,
    w_effect: float = 1.0,
    w_context: float = 1.0,
    w_signif: float = 1.0,
) -> pd.DataFrame:
    """Merge itemset context with pairwise significance to rank edges.

    Parameters:
        frequent_itemsets: DataFrame with columns `itemsets` (set[str]) and `support` (float)
        pairs_df: DataFrame with columns including `package1`, `package2`, `lift`, `jaccard`,
                  and optionally `pvalue`, `qvalue`, `a`, `b`, `c`, `d`
        min_itemset_size: Only consider itemsets of this size or larger for context
        w_effect, w_context, w_signif: Weights for composite evidence score

    Returns:
        DataFrame with pairwise stats plus itemset context columns:
            - k_itemsets, max_itemset_size, sum_itemset_support, max_itemset_support
            - relationship (complementary/competitive/neutral)
            - evidence_score (higher ranks stronger, well-supported edges)
    """
    if pairs_df is None or pairs_df.empty:
        return pd.DataFrame()

    # Aggregate itemset context across pairs
    agg: dict[tuple[str, str], dict[str, float]] = {}
    if frequent_itemsets is not None and not frequent_itemsets.empty:
        for _, row in frequent_itemsets.iterrows():
            itemset = row.get("itemsets")
            support = float(row.get("support", 0.0))
            try:
                items = sorted(list(itemset)) if itemset is not None else []
            except TypeError:
                items = []
            if len(items) < max(2, min_itemset_size):
                continue
            for i, j in combinations(items, 2):
                key = (i, j)
                if key not in agg:
                    agg[key] = {
                        "k_itemsets": 0,
                        "max_itemset_size": 0,
                        "sum_itemset_support": 0.0,
                        "max_itemset_support": 0.0,
                    }
                a = agg[key]
                a["k_itemsets"] += 1
                a["max_itemset_size"] = max(a["max_itemset_size"], len(items))
                a["sum_itemset_support"] += support
                a["max_itemset_support"] = max(a["max_itemset_support"], support)

    itemset_edges = (
        pd.DataFrame(
            [
                {
                    "package1": k[0],
                    "package2": k[1],
                    **v,
                }
                for k, v in agg.items()
            ]
        )
        if agg
        else pd.DataFrame(
            columns=[
                "package1",
                "package2",
                "k_itemsets",
                "max_itemset_size",
                "sum_itemset_support",
                "max_itemset_support",
            ]
        )
    )

    # Normalize pair order in pairs_df
    pairs_norm = pairs_df.copy()
    p1 = pairs_norm[["package1", "package2"]].min(axis=1)
    p2 = pairs_norm[["package1", "package2"]].max(axis=1)
    pairs_norm["package1"] = p1
    pairs_norm["package2"] = p2

    # Merge itemset context into pairs; keep pairs even if no itemset context
    merged = pairs_norm.merge(
        itemset_edges,
        on=["package1", "package2"],
        how="left",
        validate="m:m",
    )
    for col, fill in [
        ("k_itemsets", 0),
        ("max_itemset_size", 0),
        ("sum_itemset_support", 0.0),
        ("max_itemset_support", 0.0),
    ]:
        if col in merged.columns:
            merged[col] = merged[col].fillna(fill)

    # Relationship label
    def _rel(lift: float) -> str:
        try:
            if lift > 1:
                return "complementary"
            if lift < 1:
                return "competitive"
            return "neutral"
        except Exception:
            return "neutral"

    merged["relationship"] = merged["lift"].apply(_rel)

    # Evidence score
    def _score(row: pd.Series) -> float:
        lift = float(row.get("lift", 1.0))
        q = float(row.get("qvalue", np.nan))
        k = float(row.get("k_itemsets", 0.0))
        max_supp = float(row.get("max_itemset_support", 0.0))

        # Effect: positive only for the relevant side; here we emphasize complementary edges
        effect = 0.0
        if lift > 0:
            try:
                effect = max(0.0, float(np.log2(lift)))
            except Exception:
                effect = 0.0

        # Context: presence in itemsets and their strongest support
        context = float(np.log1p(k)) + max_supp

        # Significance: stronger for small q-values; handle missing q by 0
        if np.isnan(q):
            signif = 0.0
        else:
            q = max(min(q, 1.0), 1e-300)
            signif = max(0.0, float(-np.log10(q)))

        # Weighted sum
        denom = max(w_effect + w_context + w_signif, 1e-9)
        return (w_effect * effect + w_context * context + w_signif * signif) / denom

    merged["evidence_score"] = merged.apply(_score, axis=1)

    # Sort by strongest evidence first
    merged = merged.sort_values(
        ["evidence_score", "k_itemsets", "lift"], ascending=[False, False, False]
    )

    return merged.reset_index(drop=True)

"""Export utilities for interactive graph exploration (Sigma.js).

Provides helpers to convert analysis outputs into a graph JSON and
an optional one-shot export pipeline that runs the analyses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from .core import Service
from .stats import calculate_software_usage


def to_graph_json(
    services: list[Service],
    edges_df: pd.DataFrame,
    *,
    q_max: float = 0.05,
    min_joint: int = 3,
    max_edges: int = 2000,
    relationships: set[str] | None = None,
) -> dict:
    """Convert services + reconciled edges into a Sigma.js-friendly JSON dict.

    edges_df is expected to include: package1, package2, relationship, evidence_score,
    and ideally qvalue and 'a' (joint count). If those are missing, filtering degrades gracefully.
    """
    total_services = len(services)
    usage = calculate_software_usage(services)

    # Nodes from usage
    nodes = [
        {
            "id": pkg,
            "label": pkg,
            "usage_count": int(count),
            "support": (count / total_services) if total_services else 0.0,
        }
        for pkg, count in usage.items()
    ]

    df = edges_df.copy()
    if relationships is not None and "relationship" in df.columns:
        df = df[df["relationship"].isin(relationships)]

    if "qvalue" in df.columns:
        df = df[df["qvalue"] <= q_max]

    if "a" in df.columns:
        df = df[df["a"] >= min_joint]

    if "evidence_score" in df.columns:
        df = df.sort_values("evidence_score", ascending=False).head(max_edges)
    else:
        df = df.head(max_edges)

    edges: list[dict] = []
    for r in df.itertuples(index=False):
        p1 = r.package1
        p2 = r.package2
        rel = getattr(r, "relationship", "complementary")
        lift = float(getattr(r, "lift", 1.0))
        jacc = float(getattr(r, "jaccard", 0.0))
        qval = float(getattr(r, "qvalue", 1.0)) if hasattr(r, "qvalue") else 1.0
        joint = int(getattr(r, "a", 0)) if hasattr(r, "a") else 0
        ksets = int(getattr(r, "k_itemsets", 0)) if hasattr(r, "k_itemsets") else 0
        maxsupp = (
            float(getattr(r, "max_itemset_support", 0.0))
            if hasattr(r, "max_itemset_support")
            else 0.0
        )
        score = (
            float(getattr(r, "evidence_score", 0.0))
            if hasattr(r, "evidence_score")
            else 0.0
        )
        eid = f"{p1}|{p2}"
        edges.append(
            {
                "id": eid,
                "source": p1,
                "target": p2,
                "relationship": rel,
                "lift": lift,
                "jaccard": jacc,
                "qvalue": qval,
                "a": joint,
                "k_itemsets": ksets,
                "max_itemset_support": maxsupp,
                "evidence_score": score,
            }
        )

    return {"nodes": nodes, "edges": edges}


def write_graph_json(data: dict, out_path: str | Path) -> None:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def export_graph(
    services: list[Service],
    *,
    top_n: int | None = 60,
    min_joint_count: int = 2,
    min_support: float = 0.01,
    min_jaccard: float = 0.1,
    q_max: float = 0.05,
    relationships: set[str] | None = None,
    max_edges: int = 2000,
) -> dict:
    """One-shot pipeline to compute reconciled edges and return graph JSON.

    This is a convenience wrapper that uses advanced + stats modules.
    """
    from . import analyze_software_associations
    from .advanced import (
        add_fisher_fdr,
        compute_pair_metrics,
        reconcile_itemsets_with_pairs,
    )

    pairs = compute_pair_metrics(services, top_n=top_n, min_joint_count=min_joint_count)
    pairs_sig = add_fisher_fdr(pairs) if not pairs.empty else pairs

    frequent_itemsets, _, _ = analyze_software_associations(
        services, min_support=min_support, min_jaccard=min_jaccard
    )

    reconciled = reconcile_itemsets_with_pairs(frequent_itemsets, pairs_sig)
    graph = to_graph_json(
        services,
        reconciled,
        q_max=q_max,
        min_joint=min_joint_count,
        max_edges=max_edges,
        relationships=relationships,
    )
    return graph

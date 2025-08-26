#!/usr/bin/env python3
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET

# -------- util --------


def have(cmd):
    return shutil.which(cmd) is not None


def run(cmd, input_bytes=None, check=True, text=False):
    p = subprocess.run(cmd, input=input_bytes, capture_output=True, check=check)
    return p.stdout.decode() if text else p.stdout


def safe_paths(candidate):
    # 7z sometimes wants "./path" for cpio entries; try both
    return (
        [candidate, f"./{candidate}"]
        if not candidate.startswith("./")
        else [candidate, candidate[2:]]
    )


# -------- 7z parsers --------


def list_cpio_entries_slt(payload_path):
    """
    Use `7z l -slt` to list entries inside a cpio Payload. Returns list of dicts:
      {"Path": "...", "Size": int, "Folder": "0/1"}
    """
    out = run(["7z", "l", "-slt", payload_path], text=True)
    entries, cur = [], {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if cur.get("Path") is not None:
                # Normalize leading "./"
                p = cur["Path"]
                if p.startswith("./"):
                    p = p[2:]
                cur["Path"] = p
                # cast size
                try:
                    cur["Size"] = int(cur.get("Size", "0"))
                except:
                    cur["Size"] = 0
                entries.append(cur)
            cur = {}
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur[k] = v
    if cur.get("Path") is not None:
        p = cur["Path"]
        if p.startswith("./"):
            p = p[2:]
        cur["Path"] = p
        try:
            cur["Size"] = int(cur.get("Size", "0"))
        except:
            cur["Size"] = 0
        entries.append(cur)
    return entries


def extract_from_cpio(payload_path, inner_path):
    """
    Extract a single file from cpio Payload using 7z -> bytes.
    """
    last_err = None
    for p in safe_paths(inner_path):
        try:
            return run(["7z", "x", "-so", payload_path, p], check=True)
        except subprocess.CalledProcessError as e:
            last_err = e
    if last_err:
        raise last_err


# -------- parsers for metadata --------

VERSION_KEYS = {
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "BundleVersion",
    "KSVersion",
    "DTPlatformBuild",
    "BuildMachineOSBuild",
}


def parse_plist_bytes(b):
    try:
        return plistlib.loads(b)
    except Exception:
        return None


def parse_packageinfo_xml(path: Path):
    try:
        root = ET.parse(path).getroot()  # <pkg-info ...>
        return {
            "identifier": root.attrib.get("identifier"),
            "version": root.attrib.get("version"),
            "install_location": root.attrib.get("install-location", "/"),
        }
    except Exception as e:
        return {"error": f"PackageInfo parse failed: {e}"}


def parse_distribution_xml(path: Path):
    """
    Return list of pkg-refs with id + version if present.
    """
    results = []
    try:
        root = ET.parse(path).getroot()
        for pr in root.findall(".//pkg-ref"):
            entry = {}
            if "id" in pr.attrib:
                entry["id"] = pr.attrib["id"]
            if "version" in pr.attrib:
                entry["version"] = pr.attrib["version"]
            if pr.text and pr.text.strip().endswith(".pkg"):
                entry["pkg_path"] = pr.text.strip()
            if entry:
                results.append(entry)
    except Exception:
        pass
    return results


# Heuristic version regex: captures 1.2 / 1.2.3 / 1.2.3.4 plus optional build
RGX_VERSION = re.compile(
    r"(?i)\b(?:ver(?:sion)?\s*[:=]?\s*)?"
    r"(\d+\.\d+(?:\.\d+){0,3}(?:[+\-][0-9A-Za-z._]+)?)"
    r"(?:\s*\(?(?:build|b)\s*[:#]?\s*([0-9A-Za-z._\-]+)\)?)?"
)

TEXTY_EXTS = {".txt", ".md", ".rtf", ".nfo", ".cfg", ".cnf", ".conf"}
VERSION_NAME_HINTS = re.compile(
    r"(?i)(^|/)(version|ver|release|changelog|changes|about)\b.*"
)


def sniff_versions_from_bytes(data: bytes, max_len=512 * 1024):
    """
    Heuristic scan: look for 'version' strings and semantic versions in small files.
    For binaries, fall back to a light strings() pass.
    """
    candidates = []

    def add(match):
        ver = match.group(1)
        bld = match.group(2)
        candidates.append({"version": ver, **({"build": bld} if bld else {})})

    # Try as text first
    try:
        text = data.decode("utf-8", errors="ignore")
        for m in RGX_VERSION.finditer(text):
            add(m)
        if candidates:
            return candidates
    except Exception:
        pass

    # Light strings() for binaries
    if len(data) <= max_len:
        try:
            s = re.findall(rb"[ -~]{4,}", data)  # printable ascii runs
            joined = b"\n".join(s).decode("utf-8", errors="ignore")
            for m in RGX_VERSION.finditer(joined):
                add(m)
        except Exception:
            pass

    return candidates


# -------- main scanners --------
def deep_scan_component_pkg(comp_dir: Path):
    res = {"component": str(comp_dir), "markers": []}
    payload = comp_dir / "Payload"
    pkginfo = comp_dir / "PackageInfo"
    scripts = comp_dir / "Scripts"  # optional

    def list_entries(p):  # cpio entries via 7z
        out = run(["7z", "l", "-slt", str(p)], text=True)
        entries, cur = [], {}
        for line in out.splitlines() + [""]:
            line = line.strip()
            if not line:
                if cur.get("Path"):
                    path = (
                        cur["Path"][2:] if cur["Path"].startswith("./") else cur["Path"]
                    )
                    size = int(cur.get("Size", "0") or 0)
                    entries.append((path, size))
                cur = {}
            elif "=" in line:
                k, v = line.split("=", 1)
                cur[k] = v
        return entries

    if pkginfo.exists():
        pi = parse_packageinfo_xml(pkginfo)
        res["markers"].append({"kind": "PackageInfo", **pi})

    if payload.exists():
        entries = list_entries(payload)

        # launch plists → parse plist & note ProgramArguments / Label
        for path, _ in entries:
            if path.startswith(
                ("Library/LaunchDaemons/", "Library/LaunchAgents/")
            ) and path.endswith(".plist"):
                try:
                    data = extract_from_cpio(str(payload), path)
                    pl = parse_plist_bytes(data)
                    if pl:
                        hit = {"kind": "LaunchPlist", "path": path}
                        for k in ("Label", "Version", "Program", "ProgramArguments"):
                            if k in pl:
                                hit[k] = pl[k]
                        res["markers"].append(hit)
                except:
                    pass

        # any Info.plist anywhere
        for path, _ in entries:
            if path.endswith("Info.plist"):
                try:
                    data = extract_from_cpio(str(payload), path)
                    pl = parse_plist_bytes(data)
                    if pl:
                        res["markers"].append(
                            {
                                "kind": "BundleInfo",
                                "path": path,
                                "CFBundleIdentifier": pl.get("CFBundleIdentifier"),
                                "CFBundleShortVersionString": pl.get(
                                    "CFBundleShortVersionString"
                                ),
                                "CFBundleVersion": pl.get("CFBundleVersion"),
                            }
                        )
                except:
                    pass

        # quick strings on likely binaries from ProgramArguments
        prog_paths = []
        for m in res["markers"]:
            if m.get("kind") == "LaunchPlist":
                args = m.get("ProgramArguments") or []
                if isinstance(args, list):
                    for a in args:
                        a = a.lstrip("/")
                        if any(
                            a.startswith(prefix)
                            for prefix in ("usr/", "Library/", "bin/", "sbin/")
                        ):
                            prog_paths.append(a)
                if m.get("Program"):
                    prog_paths.append(str(m["Program"]).lstrip("/"))
        prog_paths = list(
            {p for p in prog_paths if any(p == e or p in e for e, _ in entries)}
        )

        def quick_strings(data: bytes, cap=1024 * 1024):
            if len(data) > cap:
                data = data[:cap]
            ss = re.findall(rb"[ -~]{5,}", data)
            joined = b"\n".join(ss).decode("utf-8", "ignore")
            hits = RGX_VERSION.findall(joined)
            return [{"version": v, **({"build": b} if b else {})} for v, b in hits]

        for p in prog_paths:
            try:
                blob = extract_from_cpio(str(payload), p)
                hits = quick_strings(blob)
                if hits:
                    res["markers"].append(
                        {"kind": "BinaryStrings", "path": p, "hits": hits[:5]}
                    )
            except:
                pass

        # version-ish text files
        for path, size in entries:
            if size > 256 * 1024:
                continue
            if VERSION_NAME_HINTS.search(path):
                try:
                    data = extract_from_cpio(str(payload), path)
                    hits = sniff_versions_from_bytes(data)
                    if hits:
                        res["markers"].append(
                            {"kind": "TextVersion", "path": path, "hits": hits[:5]}
                        )
                except:
                    pass

    # also scan Scripts (if present)
    if scripts.exists():
        # archive might be a cpio or just a dir; try 7z list first
        try:
            entries = run(["7z", "l", "-slt", str(scripts)], text=True)
            is_archive = "Path = " in entries
        except:
            is_archive = False

        def read_scripts_member(mem):
            if is_archive:
                for cand in safe_paths(mem):
                    try:
                        return run(["7z", "x", "-so", str(scripts), cand])
                    except:
                        pass
                return None
            p = scripts / mem
            return p.read_bytes() if p.exists() else None

        # common script names
        for mem in (
            "postinstall",
            "preinstall",
            "postupgrade",
            "preupgrade",
            "install.sh",
        ):
            blob = read_scripts_member(mem)
            if blob:
                hits = sniff_versions_from_bytes(blob)
                if hits:
                    res["markers"].append(
                        {"kind": "Script", "path": f"Scripts/{mem}", "hits": hits[:5]}
                    )

    return res


def scan_product_pkg(prod_pkg_path: Path, tmpdir: Path):
    """
    Extract nested component pkgs, parse Distribution if present, scan components.
    """
    outdir = tmpdir / f"nested_{prod_pkg_path.stem}"
    outdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["7z", "x", str(prod_pkg_path), "-o" + str(outdir), "-y"], check=True
    )

    result = {
        "product_pkg": str(prod_pkg_path),
        "distribution_refs": [],
        "components": [],
    }

    # Distribution at product level
    dist_path = outdir / "Distribution"
    if dist_path.exists():
        result["distribution_refs"] = parse_distribution_xml(dist_path)

    # Find component pkgs: directories that contain PackageInfo + Payload
    comps = []
    for p in outdir.rglob("*.pkg"):
        if (p / "PackageInfo").exists() and (p / "Payload").exists():
            comps.append(p)

    for c in sorted(comps):
        result["components"].append(deep_scan_component_pkg(c))

    return result


def scan_dmg(dmg_path: Path):
    report = {"dmg": str(dmg_path), "products": []}
    with tempfile.TemporaryDirectory() as t:
        tdir = Path(t)
        subprocess.run(["7z", "x", str(dmg_path), "-o" + str(tdir), "-y"], check=True)
        pkgs = list(tdir.rglob("*.pkg"))
        if not pkgs:
            report["note"] = "No .pkg files found inside DMG"
            return report

        for pkg in sorted(pkgs):
            # If this is already a component (rare), scan directly
            if (pkg / "PackageInfo").exists() and (pkg / "Payload").exists():
                report["products"].append(
                    {
                        "product_pkg": str(pkg),
                        "distribution_refs": [],
                        "components": [scan_component_pkg(pkg)],
                    }
                )
            else:
                report["products"].append(scan_product_pkg(pkg, tdir))
    return report


# -------- CLI --------


def summarize_to_stdout(rep):
    print(f"DMG: {rep['dmg']}")
    for prod in rep.get("products", []):
        print(f"\n== Product: {prod['product_pkg']} ==")
        if prod.get("distribution_refs"):
            for r in prod["distribution_refs"]:
                parts = []
                if "id" in r:
                    parts.append(f"id={r['id']}")
                if "version" in r:
                    parts.append(f"version={r['version']}")
                if "pkg_path" in r:
                    parts.append(f"path={r['pkg_path']}")
                print("  Distribution:", ", ".join(parts))
        if not prod.get("components"):
            print("  (no components)")
            continue
        for comp in prod["components"]:
            print(f"  -- Component: {comp['component']}")
            if comp.get("packageinfo"):
                pi = comp["packageinfo"]
                if "error" in pi:
                    print(f"     PackageInfo: {pi['error']}")
                else:
                    print(
                        f"     PackageInfo: id={pi.get('identifier')} version={pi.get('version')} install-location={pi.get('install_location')}"
                    )
            if comp.get("info_plists"):
                for ip in comp["info_plists"]:
                    print(f"     Info.plist: {ip['path']}")
                    print(f"       CFBundleIdentifier: {ip.get('CFBundleIdentifier')}")
                    print(
                        f"       CFBundleShortVersionString: {ip.get('CFBundleShortVersionString')}"
                    )
                    print(f"       CFBundleVersion: {ip.get('CFBundleVersion')}")
            if comp.get("launch_plists"):
                for lp in comp["launch_plists"]:
                    print(f"     Launch Plist: {lp['path']}")
                    for k, v in lp.items():
                        if k != "path":
                            print(f"       {k}: {v}")
            if comp.get("text_versions"):
                for tv in comp["text_versions"]:
                    hits = "; ".join(
                        [
                            f"{h['version']}"
                            + (f" (build {h['build']})" if "build" in h else "")
                            for h in tv["hits"][:3]
                        ]
                    )
                    print(f"     Text version: {tv['path']} -> {hits}")
            if comp.get("heuristic_versions"):
                for hv in comp["heuristic_versions"][:5]:
                    hits = "; ".join(
                        [
                            f"{h['version']}"
                            + (f" (build {h['build']})" if "build" in h else "")
                            for h in hv["hits"]
                        ]
                    )
                    print(f"     Heuristic: {hv['path']} -> {hits}")
            if not any(
                [
                    comp.get("info_plists"),
                    comp.get("launch_plists"),
                    comp.get("text_versions"),
                    comp.get("heuristic_versions"),
                ]
            ):
                print("     (no obvious version markers found)")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: grab_versions_from_dmg.py <path/to/image.dmg>")
        sys.exit(1)
    if not have("7z"):
        print(
            "[!] '7z' not found in PATH. Install p7zip (Linux) or `brew install p7zip` (macOS)."
        )
        sys.exit(2)
    dmg = Path(sys.argv[1])
    if not dmg.exists():
        print(f"[!] Not found: {dmg}")
        sys.exit(1)
    report = scan_dmg(dmg)
    summarize_to_stdout(report)

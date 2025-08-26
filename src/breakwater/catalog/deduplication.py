"""Package deduplication mappings for Korean banking software.

This module provides mappings from specific package names to canonical software names,
helping to identify when multiple package entries represent the same underlying software.
"""

PACKAGE_CANONICAL_MAPPING: dict[str, str] = {
    # AhnLab Safe Transaction family
    "astx": "AhnLab Safe Transaction",
    "astxfor4insure": "AhnLab Safe Transaction",
    "ahnlabsafetx": "AhnLab Safe Transaction",
    "astx_setup": "AhnLab Safe Transaction",
    "astx_setup_1.3.0.280": "AhnLab Safe Transaction",
    "astxdn": "AhnLab Safe Transaction",
    # TouchEn family (RaonSecure)
    "touchenfirewall": "TouchEn",
    "touchenkey": "TouchEn",
    "touchenkey32": "TouchEn",
    "touchenkey64": "TouchEn",
    "touchennxkey": "TouchEn",
    "touchenweb": "TouchEn",
    "touchen_nxkey_32bit": "TouchEn",
    "touchen_nxkey_installer_32bit": "TouchEn",
    "touchen_nxkey_installer_32bit_new": "TouchEn",
    "nonext.ebz_touchen_nxkey_32bit": "TouchEn",
    # Veraport family
    "veraport": "Veraport",
    "veraport-g3-x64": "Veraport",
    "veraport-g3-x64-sha2": "Veraport",
    # Delfino family
    "delfino": "WizIn-Delfino",
    "delfino-g3": "WizIn-Delfino",
    "delfino-g3-sha2": "WizIn-Delfino",
    "wizindelfino": "WizIn-Delfino",
    # KSCertRelay family (certificate management)
    "kscertrelay": "KSCertRelay",
    "kscertrelay32": "KSCertRelay",
    "kscertrelay64": "KSCertRelay",
    "kscertrelaynx": "KSCertRelay",
    "kscertrelay_nx": "KSCertRelay",
    "kscertrelay_nx_installer_32bit": "KSCertRelay",
    # AnySign family
    "anysign": "AnySign",
    "anysign4pc": "AnySign",
    "anysign_installer": "AnySign",
    # NOS family
    "nos": "nProtect Online Security",
    "nosall": "nProtect Online Security",
    "nostypea": "nProtect Online Security",
    "nos_setup": "nProtect Online Security",
    # Simple duplicates
    "apsengine": "APS Engine",
    "aps_engine": "APS Engine",
    "ipinside": "IPInside",
    "markany": "MarkAny",
    "markanyimagesafer": "MarkAny",
    "keysharpbiz": "KeySharp",
    "keysharnxbiz": "KeySharp",
    "keysharp biz": "KeySharp",
    "magicline": "MagicLine",
    "magicline4nx": "MagicLine",
    "i3gsvcmanager": "IPInside",
    "isasservice": "iSAS Service",
    "isasservice_v2.6.5": "iSAS Service",
    # INISAFE suite
    "inisafecrossweb": "INISAFE CrossWeb EX",
    "inisafecrosswebex": "INISAFE CrossWeb EX",
    "inis_ex": "INISAFE CrossWeb EX",
    "inis_ex_sha2": "INISAFE CrossWeb EX",
    # ezPDF suite
    "ezpdf": "ezPDF",
    "ezpdfprint": "ezPDF",
    "ezpdfreader": "ezPDF",
    # Setup/installer variants
    "scwssp": "SCWSSP",
    "scwsspsetup": "SCWSSP",
    "printmade3": "Printmade",
    "printmade3_setup": "Printmade",
    "setup_epagesafer(rt-html)": "ePageSafer",
    "setup_epagesaferrt": "ePageSafer",
    "epagesafer": "ePageSafer",
    "busanpfms": "BusanPFMS",
    "busanpfms_setup": "BusanPFMS",
    "tdclientagent": "TDClient",
    "tdclientforwindowsagentnx_4.9.0.5": "TDClient",
    "vestcert": "VestCert",
    "vertcert": "VestCert",
    "cx60": "CX60",
    "cx60_ocx": "CX60",
}


def get_canonical_name(package_name: str) -> str:
    """Get the canonical name for a package, or the original name if no mapping exists."""
    return PACKAGE_CANONICAL_MAPPING.get(package_name.lower(), package_name)


def get_canonical_packages() -> set[str]:
    """Get the set of all canonical package names."""
    return set(PACKAGE_CANONICAL_MAPPING.values())


def get_package_variants(canonical_name: str) -> list[str]:
    """Get all package variant names that map to a canonical name."""
    return [
        pkg
        for pkg, canonical in PACKAGE_CANONICAL_MAPPING.items()
        if canonical == canonical_name
    ]


def deduplicate_package_list(package_names: list[str]) -> dict[str, list[str]]:
    """Group package names by their canonical names.

    Returns:
        Dict mapping canonical names to lists of variant names
    """
    result = {}

    for package_name in package_names:
        canonical = get_canonical_name(package_name)
        if canonical not in result:
            result[canonical] = []
        result[canonical].append(package_name)

    return result


def count_unique_software(package_names: list[str]) -> int:
    """Count the number of unique software packages (after deduplication)."""
    return len(set(get_canonical_name(name) for name in package_names))

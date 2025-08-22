"""Download source files for packages."""

from pathlib import Path
from typing import Any

import requests
import yaml


def load_manifest(package: str) -> dict[str, Any]:
    manifest_path = Path("manifests") / f"{package}.yaml"

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path) as f:
        return yaml.safe_load(f)


def download_file(url: str, output_path: Path):
    try:
        print(f"Downloading: {url}")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"Downloaded to: {output_path}")
        return True

    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False


def download_sources(package: str):
    try:
        manifest = load_manifest(package)
        target_dir = Path(manifest["target_dir"])
        package_dir = target_dir / "packages"

        # Create package and source directories
        package_dir.mkdir(parents=True, exist_ok=True)

        sources = manifest.get("sources", {})
        if not sources:
            print(f"No sources defined in manifest for {package}")
            return True

        # Download all sources
        success = True
        for target_name, url in sources.items():
            # Determine filename from URL
            filename = url.split("/")[-1]
            if not filename or "." not in filename:
                # Fallback filename
                filename = f"{target_name}_file"

            output_path = package_dir / filename

            # Skip if file already exists
            if output_path.exists():
                print(f"File already exists, skipping: {output_path}")
                continue

            if not download_file(url, output_path):
                success = False

        return success

    except Exception as e:
        print(f"Error downloading sources for {package}: {e}")
        return False

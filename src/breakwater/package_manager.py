import hashlib
import logging
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, NoReturn, assert_never, cast

import requests
import xattr
import yaml
from packaging import version
from pydantic import BaseModel

logger = logging.getLogger(__name__)

PackageExtension = Literal[".deb", ".dmg", ".exe"]


def get_xattr_str(file_path: Path, attr_name: str) -> str:
    """Get xattr value as decoded string."""
    return cast("bytes", xattr.getxattr(file_path, attr_name)).decode("utf-8")


class Package(BaseModel):
    target: str
    architecture: str
    checksum: str
    url: str
    downloaded_at: datetime
    version: str | None = None
    base_dir: Path = Path(".")

    @property
    def original_filename(self):
        """Original filename from URL."""
        return Path(self.url.split("/")[-1])

    @property
    def extension(self):
        """Package file extension."""
        ext = self.original_filename.suffix
        if ext in (".deb", ".dmg", ".exe"):
            return cast("PackageExtension", ext)
        else:
            raise ValueError(f"Unsupported package extension: {ext}")

    @property
    def download_path(self):
        """Canonical download path."""
        filename_path = Path(self.original_filename)
        return (
            self.base_dir
            / "targets"
            / self.target
            / "downloads"
            / f"{filename_path.stem}.{self.checksum[:16]}{filename_path.suffix}"
        )

    @property
    def unpack_path(self):
        """Canonical unpack path."""
        return (
            self.base_dir
            / "targets"
            / self.target
            / "unpacked"
            / f"{self.architecture}_{self.checksum[:16]}"
        )

    @classmethod
    def from_file(cls, file_path: Path, base_dir: Path):
        """Load Package from existing file with xattrs."""
        if not file_path.exists():
            raise FileNotFoundError(f"Package file not found: {file_path}")

        url = get_xattr_str(file_path, "user.breakwater.url")
        checksum = get_xattr_str(file_path, "user.breakwater.checksum")
        downloaded_at_str = get_xattr_str(file_path, "user.breakwater.downloaded_at")
        architecture = get_xattr_str(file_path, "user.breakwater.architecture")

        # Extract target from file path
        # Path structure: base_dir/targets/TARGET/downloads/filename
        parts = file_path.parts
        target_idx = parts.index("targets") + 1
        target = parts[target_idx]

        # Try to get version, might not exist
        try:
            version = get_xattr_str(file_path, "user.breakwater.version")
        except OSError:
            version = None

        return cls(
            target=target,
            architecture=architecture,
            checksum=checksum,
            url=url,
            downloaded_at=datetime.fromisoformat(downloaded_at_str),
            version=version,
            base_dir=base_dir,
        )

    def save_metadata(self):
        """Save metadata to xattrs on download_path."""
        file_path = self.download_path
        xattr.setxattr(file_path, "user.breakwater.url", self.url.encode("utf-8"))
        xattr.setxattr(
            file_path, "user.breakwater.checksum", self.checksum.encode("utf-8")
        )
        xattr.setxattr(
            file_path,
            "user.breakwater.downloaded_at",
            self.downloaded_at.isoformat().encode("utf-8"),
        )
        xattr.setxattr(
            file_path, "user.breakwater.architecture", self.architecture.encode("utf-8")
        )

        if self.version is not None:
            xattr.setxattr(
                file_path, "user.breakwater.version", self.version.encode("utf-8")
            )

    def __lt__(self, other: "Package"):
        """Version comparison for sorting."""
        if self.version is None and other.version is None:
            return False
        if self.version is None:
            return True  # None versions sort first
        if other.version is None:
            return False

        # Use packaging.version for semantic comparison
        return version.parse(self.version) < version.parse(other.version)


class DownloadResult(BaseModel):
    package: Package
    was_downloaded: bool
    was_overwritten: bool = False


class UnpackResult(BaseModel):
    package: Package
    unpack_path: Path
    was_unpacked: bool
    was_overwritten: bool = False


class PackageManager:
    def __init__(self, base_dir: Path = Path("."), overwrite: bool = False):
        self.base_dir = base_dir
        self.targets_dir = base_dir / "targets"
        self.manifest_path = base_dir / "src/breakwater/manifest.yml"
        self.overwrite = overwrite

    def load_manifest(self) -> dict[str, Any]:
        """Load the unified targets manifest."""
        if not self.manifest_path.exists():
            return {}

        with open(self.manifest_path) as f:
            return yaml.safe_load(f)

    def save_manifest(self, manifest: dict[str, Any]):
        """Save the updated manifest with checksums."""
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.manifest_path, "w") as f:
            yaml.dump(manifest, f, default_flow_style=False, sort_keys=False)

    def compute_checksum(self, file_path: Path):
        """Compute SHA256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def download_package(
        self,
        target: str,
        architecture: str,
    ) -> DownloadResult:
        """Download a package with checksum tracking and version extraction."""

        manifest = self.load_manifest()

        # Get package info
        if target not in manifest:
            raise ValueError(f"Unknown target: {target}")

        target_info = manifest[target]

        if architecture not in target_info:
            raise ValueError(f"Unknown architecture: {architecture}")

        pkg_info = target_info[architecture]
        url = pkg_info["url"]

        package = Package(
            target=target,
            architecture=architecture,
            checksum="",
            url=url,
            downloaded_at=datetime.now(),
            version=None,
            base_dir=self.base_dir,
        )

        package.download_path.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Downloading %s", url)
        try:
            response = requests.get(url, stream=True)
            response.raise_for_status()

            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_path = Path(temp_file.name)

        except Exception as e:
            raise RuntimeError(f"Download failed: {e}") from e

        checksum = self.compute_checksum(temp_path)
        logger.info("Checksum: %s", checksum)

        package.checksum = checksum

        was_overwritten = False
        if package.download_path.exists():
            if not self.overwrite:
                temp_path.unlink()
                existing_package = Package.from_file(
                    package.download_path, self.base_dir
                )
                return DownloadResult(package=existing_package, was_downloaded=False)
            else:
                was_overwritten = True

        temp_path.rename(package.download_path)

        extracted_version = self.extract_package_version(package)
        package.version = extracted_version

        package.save_metadata()

        logger.info("Downloaded to: %s", package.download_path)
        return DownloadResult(
            package=package, was_downloaded=True, was_overwritten=was_overwritten
        )

    def list_downloaded_files(self, target: str) -> list[Package]:
        """List all downloaded files for a target."""
        download_dir = self.targets_dir / target / "downloads"
        if not download_dir.exists():
            return []

        packages = []
        for file_path in download_dir.iterdir():
            if file_path.is_file() and not file_path.name.endswith(".downloading"):
                package = Package.from_file(file_path, self.base_dir)
                packages.append(package)

        return packages

    def get_latest_version_download(
        self, target: str, architecture: str
    ) -> list[Package]:
        """Get packages with the highest semantic version for target/architecture.

        Returns list of packages (can be multiple if same version).
        """
        packages = self.list_downloaded_files(target)

        # Filter by architecture and only include packages with version info
        arch_packages = [
            p
            for p in packages
            if p.architecture == architecture and p.version is not None
        ]
        if not arch_packages:
            return []

        # Sort by semantic version (highest first)
        arch_packages.sort(reverse=True)  # Uses Package.__lt__

        # Return all packages with the highest version
        highest_version = arch_packages[0].version
        return [p for p in arch_packages if p.version == highest_version]

    def find_package_by_checksum(self, target: str, architecture: str, checksum: str):
        """Find a package by target, architecture, and exact checksum.

        Returns:
            Package if found, None otherwise
        """
        packages = self.list_downloaded_files(target)
        matching = [
            p
            for p in packages
            if p.architecture == architecture and p.checksum == checksum
        ]
        return matching[0] if matching else None

    def get_current_link(self, target: str):
        """Get the current symlink path for a target."""
        return self.targets_dir / target / "current"

    def is_package_current(self, package: Package):
        """Check if a package is the current symlinked version."""
        current_link = self.get_current_link(package.target)

        if not (current_link.exists() and current_link.is_symlink()):
            return False

        resolved_path = current_link.resolve()
        return resolved_path == package.unpack_path.resolve()

    def extract_deb_version(self, package: Package) -> str:
        """Extract version from .deb package using containerized dpkg-deb."""
        workspace = package.base_dir
        container_pkg_path = (
            f"/workspace/{package.download_path.relative_to(workspace)}"
        )

        result = subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{workspace}:/workspace",
                "debian:bookworm-slim",
                "dpkg-deb",
                "-f",
                container_pkg_path,
                "Version",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def extract_dmg_version(self, package: Package):
        """Extract version from .dmg package - stub implementation."""
        return None

    def extract_exe_version(self, package: Package):
        """Extract version from .exe package - stub implementation."""
        return None

    def extract_package_version(self, package: Package):
        """Extract version from package based on file extension."""
        extension = package.extension
        if extension == ".deb":
            return self.extract_deb_version(package)
        elif extension == ".dmg":
            return self.extract_dmg_version(package)
        elif extension == ".exe":
            return self.extract_exe_version(package)
        else:
            assert_never(extension)

    def unpack_deb(self, package: Package):
        """Unpack .deb using containerized dpkg-deb"""
        # Create rootfs and meta directories
        (package.unpack_path / "rootfs").mkdir(parents=True, exist_ok=True)
        (package.unpack_path / "meta").mkdir(parents=True, exist_ok=True)

        # Use podman with debian container
        # Mount parent directories for access
        workspace = package.base_dir
        container_pkg_path = (
            f"/workspace/{package.download_path.relative_to(workspace)}"
        )
        container_unpack_path = (
            f"/workspace/{package.unpack_path.relative_to(workspace)}"
        )

        # Extract files with dpkg-deb
        command = (
            f"dpkg-deb -x {container_pkg_path} {container_unpack_path}/rootfs && "
            f"dpkg-deb -e {container_pkg_path} {container_unpack_path}/meta"
        )

        subprocess.run(
            [
                "podman",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{workspace}:/workspace",
                "debian:bookworm-slim",
                "sh",
                "-c",
                command,
            ],
            check=True,
        )

    def unpack_dmg(self, package: Package) -> NoReturn:
        """Unpack .dmg files - not implemented yet."""
        raise NotImplementedError("macOS .dmg unpacking not implemented yet")

    def unpack_exe(self, package: Package) -> NoReturn:
        """Unpack .exe files - not implemented yet."""
        raise NotImplementedError("Windows .exe unpacking not implemented yet")

    def unpack_package(self, package: Package) -> UnpackResult:
        """Unpack a package to its canonical unpack directory."""

        logger.info("Unpacking %s", package.download_path)

        package_path = package.download_path
        if not package_path.exists():
            raise FileNotFoundError(f"Package not found: {package_path}")

        unpack_dir = package.unpack_path
        was_overwritten = False

        if unpack_dir.exists():
            if not self.overwrite:
                return UnpackResult(
                    package=package, unpack_path=unpack_dir, was_unpacked=False
                )
            else:
                was_overwritten = True
                shutil.rmtree(unpack_dir)

        unpack_dir.mkdir(parents=True, exist_ok=True)

        # Determine unpacking method based on file type
        extension = package.extension
        if extension == ".deb":
            self.unpack_deb(package)
        elif extension == ".dmg":
            self.unpack_dmg(package)
        elif extension == ".exe":
            self.unpack_exe(package)
        else:
            assert_never(extension)

        return UnpackResult(
            package=package,
            unpack_path=unpack_dir,
            was_unpacked=True,
            was_overwritten=was_overwritten,
        )

    def set_current(self, target: str, unpack_dir: Path):
        """Set the current symlink to point to an unpacked version."""
        current_link = self.get_current_link(target)

        # Remove old symlink
        if current_link.exists() or current_link.is_symlink():
            current_link.unlink()

        # Create new symlink (relative)
        relative_path = Path("unpacked") / unpack_dir.name
        current_link.symlink_to(relative_path)
        logger.info("Set current -> %s", relative_path)

    def download_and_unpack(
        self,
        target: str,
        architecture: str,
        set_current: bool = True,
    ):
        """Download and unpack a package in one step."""

        # Download
        download_result = self.download_package(target, architecture)

        # Unpack
        unpack_result = self.unpack_package(download_result.package)

        # Set as current if requested
        if set_current:
            self.set_current(target, unpack_result.unpack_path)

        return unpack_result.unpack_path

from datetime import datetime
from pathlib import Path
from typing import Literal, cast

import xattr
from packaging import version
from pydantic import BaseModel

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

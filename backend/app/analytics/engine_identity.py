import json
import os
from pathlib import Path
from pydantic import BaseModel
from typing import Optional, Literal

class SubstrateMetadata(BaseModel):
    python_implementation: str
    python_version: str
    platform_system: str
    machine: str
    libc_name: str
    libc_version: str
    substrate_completeness: Literal["COMPLETE", "INCOMPLETE"]

class EngineMetadata(BaseModel):
    engine_digest: str
    source_version: str
    dirty: bool
    source_tree_digest: str
    dependency_digest: str
    substrate_digest: str
    lockfile_digest: str
    substrate_metadata: SubstrateMetadata
    dependency_metadata: list[str]

class EngineIdentityService:
    """Service to load and verify engine provenance (J-5 and ART-25)."""

    def __init__(self, metadata_path: str = "/app/engine_metadata.json"):
        self.metadata_path = Path(metadata_path)

    def get_metadata(self) -> Optional[EngineMetadata]:
        if not self.metadata_path.exists():
            return None

        with open(self.metadata_path, "r") as f:
            data = json.load(f)
            return EngineMetadata(**data)

    def check_immutability(self) -> str:
        """ART-25: Verification of metadata immutability."""
        if not self.metadata_path.exists():
            return "ENGINE_UNVERIFIABLE(missing_metadata)"

        try:
            stat = self.metadata_path.stat()
        except OSError:
            return "ENGINE_UNVERIFIABLE(metadata_unreadable)"

        # Is it a symlink? (In python 3.12+, .stat(follow_symlinks=False))
        try:
            lstat = self.metadata_path.lstat()
            import stat as stat_mod
            if stat_mod.S_ISLNK(lstat.st_mode):
                return "ENGINE_UNVERIFIABLE(metadata_is_symlink)"
        except OSError:
            pass

        # Check permissions: must be mode 0444 (read-only for all)
        # stat.st_mode & 0o777 extracts the permission bits
        import stat as stat_mod
        perms = stat_mod.S_IMODE(stat.st_mode)
        if perms != 0o444:
            return f"ENGINE_UNVERIFIABLE(metadata_not_0444)"

        # Must be root-owned
        if hasattr(stat, 'st_uid') and stat.st_uid != 0:
            if os.name != 'nt': # skip uid 0 check on Windows local tests
                return "ENGINE_UNVERIFIABLE(metadata_not_root_owned)"

        # Verify unprivileged execution
        if hasattr(os, 'geteuid'):
            if os.geteuid() == 0:
                return "ENGINE_UNVERIFIABLE(runtime_is_root)"

            # Is parent directory writable by the effective user?
            parent = self.metadata_path.parent
            if os.access(parent, os.W_OK):
                return "ENGINE_UNVERIFIABLE(parent_directory_writable)"

            # Is the file itself writable by the effective user?
            if os.access(self.metadata_path, os.W_OK):
                return "ENGINE_UNVERIFIABLE(metadata_writable)"

        # Verify Substrate completeness
        metadata = self.get_metadata()
        if not metadata:
            return "ENGINE_UNVERIFIABLE(malformed_metadata)"

        if metadata.substrate_metadata.substrate_completeness == "INCOMPLETE":
            return "ENGINE_UNVERIFIABLE(substrate_incomplete)"

        if metadata.dirty:
            return "ENGINE_UNVERIFIABLE(dirty_source)"

        import platform
        # Check runtime patch version mismatch
        if metadata.substrate_metadata.python_version != platform.python_version():
            return "ENGINE_UNVERIFIABLE(python_version_mismatch)"

        return "VERIFIED"

    def authorize_persistence(self) -> bool:
        """Determines if the current engine state is permitted to persist artifacts."""
        return self.check_immutability() == "VERIFIED"

import json
import os
import re
from pathlib import Path
from pydantic import BaseModel, Field, StrictBool
from typing import Annotated, Optional, Literal

# SEC-30: advisory source provenance must still be a real commit SHA to verify.
_SOURCE_VERSION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

class SubstrateMetadata(BaseModel):
    python_implementation: str
    python_version: str
    platform_system: str
    machine: str
    libc_name: str
    libc_version: str
    substrate_completeness: Literal["COMPLETE", "INCOMPLETE"]

class EngineMetadata(BaseModel):
    # Digests are SHA-256 hex; dirty must be a real boolean; the resolved
    # dependency set must be non-empty. Anything else is malformed metadata.
    engine_digest: Sha256Hex
    source_version: str
    dirty: StrictBool
    source_tree_digest: Sha256Hex
    dependency_digest: Sha256Hex
    substrate_digest: Sha256Hex
    lockfile_digest: Sha256Hex
    substrate_metadata: SubstrateMetadata
    dependency_metadata: Annotated[list[str], Field(min_length=1)]

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
        # Fail closed (SEC-21): unreadable, non-JSON, wrongly shaped or
        # incomplete metadata is unverifiable, never an exception.
        try:
            metadata = self.get_metadata()
        except (OSError, ValueError, TypeError):
            return "ENGINE_UNVERIFIABLE(malformed_metadata)"
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

        # source_version is advisory provenance (source_tree_digest is the
        # authoritative identity), but an unknown or non-SHA commit cannot be
        # traced, so it is not verifiable for persistence.
        if not _SOURCE_VERSION_PATTERN.fullmatch(metadata.source_version):
            return "ENGINE_UNVERIFIABLE(source_version_unverifiable)"

        return "VERIFIED"

    def authorize_persistence(self) -> bool:
        """Determines if the current engine state is permitted to persist artifacts."""
        return self.check_immutability() == "VERIFIED"

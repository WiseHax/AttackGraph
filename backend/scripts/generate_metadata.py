import os
import sys
import json
import hashlib
import platform
import subprocess
import fnmatch
from pathlib import Path

def get_libc_info():
    name, ver = platform.libc_ver()
    if name and ver:
        return name, ver

    # robust fallback for musl libc
    try:
        if os.path.exists("/usr/bin/ldd") or os.path.exists("/bin/ldd") or os.path.exists("/sbin/ldd"):
            output = subprocess.check_output(["ldd", "--version"], stderr=subprocess.STDOUT, text=True)
            if "musl libc" in output.lower():
                for line in output.splitlines():
                    if "Version" in line:
                        return "musl", line.split("Version")[-1].strip()
                return "musl", "unknown"
    except Exception:
        pass

    return "unknown", "unknown"

def get_substrate_info():
    libc_name, libc_ver = get_libc_info()
    completeness = "COMPLETE" if (libc_name != "unknown" and libc_ver != "unknown") else "INCOMPLETE"

    payload = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "platform_system": platform.system(),
        "machine": platform.machine(),
        "libc_name": libc_name,
        "libc_version": libc_ver,
        "substrate_completeness": completeness
    }

    digest_str = (
        "attackgraph.substrate.v1"
        + payload["python_implementation"]
        + payload["python_version"]
        + payload["platform_system"]
        + payload["machine"]
        + payload["libc_name"]
        + payload["libc_version"]
        + payload["substrate_completeness"]
    )

    return {
        "metadata": payload,
        "digest": hashlib.sha256(digest_str.encode("utf-8")).hexdigest()
    }

def normalize_pep503(name: str) -> str:
    import re
    return re.sub(r"[-_.]+", "-", name).lower()

def get_dependency_info(req_path):
    with open(req_path, 'r') as f:
        content = f.read()

    lockfile_digest = hashlib.sha256(content.encode("utf-8")).hexdigest()

    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('-'):
            continue

        # pip-compile outputs: "package==version \ --hash=..."
        pkg_str = line.split()[0]
        if '==' in pkg_str:
            name, ver = pkg_str.split('==', 1)
            norm_name = normalize_pep503(name)
            packages.append(f"{norm_name}=={ver}")

    packages.sort()

    # dependency_digest computation (normalized names and versions)
    # The prompt says: dependency_digest MUST be computed from the normalized resolved package set
    h = hashlib.sha256()
    h.update(b"attackgraph.dependencies.v1")
    for pkg in packages:
        h.update(pkg.encode("utf-8"))

    return {
        "metadata": packages,
        "digest": h.hexdigest(),
        "lockfile_digest": lockfile_digest
    }

def load_dockerignore(root):
    ignore_patterns = []
    di_path = os.path.join(root, '.dockerignore')
    if os.path.exists(di_path):
        with open(di_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if line.endswith('/'):
                        line = line[:-1]
                    ignore_patterns.append(line)
    return ignore_patterns

def is_ignored(path, patterns, root):
    rel = os.path.relpath(path, root)
    rel_forward = rel.replace('\\', '/')
    parts = rel_forward.split('/')
    for p in patterns:
        p_strip = p.strip('/')
        if p_strip in parts:
            return True
        if fnmatch.fnmatch(rel_forward, p) or fnmatch.fnmatch(os.path.basename(path), p):
            return True
    return False

def get_source_tree_info(root):
    patterns = load_dockerignore(root)
    # Exclude .git and the metadata file itself
    patterns.extend(['.git', 'engine_metadata.json'])

    file_hashes = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not is_ignored(os.path.join(dirpath, d), patterns, root)]

        for f in filenames:
            fpath = os.path.join(dirpath, f)
            if not is_ignored(fpath, patterns, root):
                rel = os.path.relpath(fpath, root).replace('\\', '/')
                # hash content
                h = hashlib.sha256()
                with open(fpath, 'rb') as fd:
                    while chunk := fd.read(8192):
                        h.update(chunk)
                file_hashes.append((rel, h.hexdigest()))

    file_hashes.sort()

    h = hashlib.sha256()
    h.update(b"attackgraph.source.v1")
    for rel, fhash in file_hashes:
        # framed: [len_path]:path|[len_hash]:hash or just simple framing
        # The prompt says: framed, sorted(relative_path + content_digest) pairs
        frame = f"{len(rel)}:{rel}|{len(fhash)}:{fhash}"
        h.update(frame.encode('utf-8'))

    return {
        "digest": h.hexdigest()
    }

def get_git_info():
    commit = os.environ.get("APP_GIT_COMMIT")
    dirty_env = os.environ.get("APP_GIT_DIRTY")

    if not commit:
        try:
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
        except Exception:
            commit = "UNKNOWN"

    if dirty_env is None:
        try:
            status = subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()
            dirty = True if status else False
        except Exception:
            dirty = True
    else:
        dirty = dirty_env.lower() == "true"

    return commit, dirty

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    substrate = get_substrate_info()
    deps = get_dependency_info(os.path.join(root, "requirements.lock"))
    source_info = get_source_tree_info(root)
    source_version, dirty = get_git_info()

    engine_digest_str = (
        "attackgraph.engine.v1"
        + source_version
        + source_info["digest"]
        + deps["digest"]
        + substrate["digest"]
    )

    engine_digest = hashlib.sha256(engine_digest_str.encode("utf-8")).hexdigest()

    metadata = {
        "engine_digest": engine_digest,
        "source_version": source_version,
        "dirty": dirty,
        "source_tree_digest": source_info["digest"],
        "dependency_digest": deps["digest"],
        "substrate_digest": substrate["digest"],
        "lockfile_digest": deps["lockfile_digest"],
        "substrate_metadata": substrate["metadata"],
        "dependency_metadata": deps["metadata"]
    }

    out_path = os.path.join(root, "engine_metadata.json")
    with open(out_path, "w") as f:
        json.dump(metadata, f, indent=2)

if __name__ == "__main__":
    main()

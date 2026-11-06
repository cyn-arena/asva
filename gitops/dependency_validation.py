"""Validation shared by npm generation and coordinated dependency submission."""


def validate_pair(manifest: dict, lock: dict) -> None:
    """Require a lockfile with a `packages` section (version 2 or 3) whose root dependency
    declarations match."""
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        raise ValueError("Dependency files must contain JSON objects")
    if lock.get("lockfileVersion") not in (2, 3):
        raise ValueError("Expected lockfile version 2 or 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        raise ValueError("Lockfile has no root package")
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        if manifest.get(section, {}) != packages[""].get(section, {}):
            raise ValueError(f"Manifest and lockfile disagree on {section}")

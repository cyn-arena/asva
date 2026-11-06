"""Request/response models: the versioned HTTP contract ASVA codes against (schema_version "1").

Additions are backwards compatible: new optional request fields, new response fields.
"""

from pydantic import BaseModel, Field

from app import config

SCHEMA_VERSION = "1"


class Finding(BaseModel):
    """The normalised finding fields ASVA sends. Unknown extra fields are ignored."""
    finding_type: str | None = Field(default=None, max_length=50)
    cve: str | None = Field(default=None, max_length=50)
    cwe: str | None = Field(default=None, max_length=50)
    # Further CWE ids the scanner tagged the rule with (dependency and container findings
    # carry theirs in the SARIF rule tags, not in `cwe`).
    cwes: list[str] | None = Field(default=None, max_length=20)
    rule_id: str | None = Field(default=None, max_length=200)
    # Optional; otherwise taken from a SAST rule_id prefix such as "javascript/CodeInjection".
    language: str | None = Field(default=None, max_length=50)
    package: str | None = Field(default=None, max_length=300)
    ecosystem: str | None = Field(default=None, max_length=50)
    upgrade_to: str | None = Field(default=None, max_length=300)
    fixable: bool | None = None
    dependency_path: list[str] | None = Field(default=None, max_length=50)
    # Container findings: the scanned image, e.g. "mongo" and "4.4".
    image_name: str | None = Field(default=None, max_length=300)
    image_tag: str | None = Field(default=None, max_length=200)
    title: str | None = Field(default=None, max_length=1_000)
    summary: str | None = Field(default=None, max_length=10_000)
    description: str | None = Field(default=None, max_length=10_000)


class Manifest(BaseModel):
    """The dependency file the findings are in (requirements.txt or package.json): the pinned and
    declared versions the trial plan checks companion upgrades against."""
    file: str = Field(max_length=300)
    content: str = Field(max_length=200_000)
    dev_only: list[str] | None = Field(default=None, max_length=20_000,
                                       description="npm: name@version of installed packages the lockfile marks dev-only")
    copies: dict[str, list[dict]] | None = Field(
        default=None, description="npm: every installed copy of the findings' packages, from the lockfile "
                                  "(asva_rag_client.npm_copies): version, dev, chain of packages from a direct dependency")


class ContextRequest(BaseModel):
    fix_type: str | None = Field(
        default=None, max_length=50,
        description="code_change | version_upgrade | logic_change | config_change",
    )
    max_chars: int = Field(default=config.DEFAULT_MAX_CHARS, ge=500, le=50_000)
    findings: list[Finding] = Field(min_length=1, max_length=500)
    debug: bool = Field(default=False, description="Also return how the context was found (search queries etc.)")
    manifest: Manifest | None = Field(default=None, description="The dependency file, for the trial plan (optional)")
    exclude_sources: list[str] | None = Field(
        default=None, max_length=20,
        description="Answer without these sources, to compare results with and without one: "
                    + ", ".join(config.SOURCE_IDS))


class ContextItem(BaseModel):
    """Prompt context. kind: guidance | cwe | upgrade_notes | container_summary | kev
    (and library_notes, only with LIBRARY_NOTES_IN_PROMPT)"""
    source: str
    key: str
    kind: str
    title: str | None
    section: str | None = None
    text: str
    url: str | None
    license: str | None
    fetched_at: str
    score: float | None = None       # similarity, guidance items found by similarity only
    matched_by: str | None = None    # guidance items: "similarity" | "keyword"


class Reference(BaseModel):
    """A citation for the PR body / UI. type: cve | cwe | advisory | guidance | library_docs | image | os_release_fix"""
    type: str
    id: str
    title: str | None = None
    url: str | None = None
    source: str
    license: str | None = None
    cvss: float | None = None
    severity: str | None = None
    cwes: list[str] | None = None
    kev: bool | None = None            # in CISA's Known Exploited Vulnerabilities catalogue
    kev_date: str | None = None
    owasp_top10: list[str] | None = None
    description: str | None = None     # cwe: MITRE's definition; library_docs: the breaking-change note
    mitigations: list[str] | None = None  # cwe: MITRE's potential mitigations, implementation first
    package: str | None = None
    fixed_in: str | None = None
    availability: str | None = None    # OS package fix: the distribution's wording, e.g. "Available with Ubuntu Pro ..."
    subscription_only: bool | None = None  # OS package fix: published only to paying subscribers, not the standard packages
    newer_release_fixes: dict[str, str] | None = None  # type os_release_fix: no fix for the image's OS release, but these newer ones have one
    release_name: str | None = None    # type os_release_fix: the image's OS release as named in an image tag, e.g. "bookworm"
    newer_release_names: dict[str, str] | None = None  # type os_release_fix: the same for the newer ones, e.g. {"13": "trixie"}
    aliases: list[str] | None = None
    beyond_target: bool | None = None  # advisory still open after upgrading to the scanner's target


class ImageLine(BaseModel):
    """One newer release line of a container image."""
    tag: str
    version: str | None = None
    base_os: str | None = None
    released: str | None = None
    supported_until: str | None = None
    end_of_life: bool | None = None
    cves_resolved: int | None = None   # of `cves_checked`: fixed in this base OS's standard repositories, or not affected
    cves_checked: int | None = None


class Companion(BaseModel):
    """Another package that has to change for a trial to install."""
    name: str
    current: str | None = None         # the app's pinned version
    suggest: str | None = None         # the smallest published version that resolves the conflict
    reason: str                        # e.g. "cryptography 49.0.0 requires cffi>=2.0.0"
    major_change: bool = False


class Fallback(BaseModel):
    """Another version to try when an upgrade does not install or breaks the app."""
    target: str
    also_needs: list[Companion] = []


class Upgrade(BaseModel):
    """What to change, machine-readable. kind: package | image

    status (package): ok | major_change | already_at_target | osv_disagrees | no_target
    status (image):   newer_line_needed | rebuild_may_suffice | unknown
    """
    kind: str
    name: str
    ecosystem: str | None = None       # packages: npm ...; images: the base OS, e.g. "Ubuntu 20.04"
    current: str | None = None
    target: str | None = None          # packages: the scanner's target; images: the compatible line, else the migration target
    target_source: str | None = None
    # A version that fixes this without a major version change (semver), i.e. the bump that is
    # safe to apply automatically. None: no such version is known, or nothing can be bumped.
    compatible_target: str | None = None
    # "all": the compatible target resolves the findings. "partial" (packages): it resolves the
    # advisories that have a fix within the installed major version; the rest need the migration (see note).
    compatible_scope: str | None = None
    min_fixed: str | None = None       # packages: smallest version OSV.dev lists as fixing the matched advisories
    major_change: bool = False
    status: str
    fixes: list[str] = []              # the finding ids (CVE or rule id) this change addresses
    candidates: list[ImageLine] | None = None
    fallbacks: list[Fallback] = []     # to try if the compatible target fails: newer versions with no known advisory
    note: str | None = None


class Trial(BaseModel):
    """A held-back upgrade to try on its own (build, start, test), in plan order. Not prompt text.

    kind: lockfile_refresh | parent_upgrade | major_upgrade | image_major"""
    order: int
    kind: str
    name: str
    current: str | None = None
    target: str | None = None
    fixes: list[str] = []              # the finding ids it fixes (lockfile_refresh: may fix)
    known_exploited: list[str] = []
    dev_only: bool = False             # only in development tools, not in the running application
    also_needs: list[Companion] = []
    fallbacks: list[Fallback] = []     # to try in this order if the target fails
    note: str | None = None


class ContextResponse(BaseModel):
    schema_version: str = SCHEMA_VERSION
    snapshot: dict[str, dict]
    items: list[ContextItem]
    references: list[Reference]
    upgrades: list[Upgrade] = []
    trials: list[Trial] = []
    warnings: list[str]
    debug: dict | None = None  # only when requested


class SyncRequest(BaseModel):
    sources: list[str] | None = Field(default=None, description="cwe | owasp | kev | nvd (default: all)")
    force: bool = False

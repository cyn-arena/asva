"""
agent/repo_context.py -- repo-aware context for the fix agent (ITP2 task 3.1).

The fix prompt normally shows the LLM exactly one file. A fix that changes something the
file exports (a DAO method, a route handler, a Django view) cannot see who calls it, so it
can silently break a caller in another file. This module builds a lightweight import index
of the target app once per batch and renders, for the file being fixed, a short read-only
note:

  - which files import it, their import line, and the lines where they use what they
    import (lines that use the function/class containing a finding are listed first)
  - which local modules it imports
  - the URL routes it serves (registered in it, or in a file that imports it) and the
    templates and code that link to those URLs, so a fix does not rename or drop a route
    parameter that a page still uses (the IDOR fix that broke /allocations/{{userId}})

It also records where each third-party package is used, so a dependency upgrade can point a
reviewer at the code that depends on that package (see package_usage_sites), and renders the
scanner's own data flow (SARIF codeFlows) for a finding, including the code of other files
on that path (see render_code_flow).

Language support sits behind the ImportResolver interface, one resolver per language,
registered in RESOLVERS. The index and the rendering are language-neutral:

  - JavaScriptResolver: CommonJS `require()`, ES modules (`import ... from`, `export ...
    from`, dynamic `import()`), and TypeScript files (NodeGoat, Juice Shop-style apps)
  - PythonResolver: `import x`, `from x import y`, relative imports, plus Django's dotted
    module strings (`include("app.urls")`, `ROOT_URLCONF = "proj.urls"`) (PyGoat)

A new target-app language plugs in by adding a resolver; nothing else changes. Files in a
language without a resolver simply get no import context (the SAST data flow still works).

Parsing is deliberately approximate: comments are stripped first so dead imports don't
become edges, and anything that can't be resolved statically (e.g.
`require(path.resolve(...))`, `importlib.import_module(name)`) simply produces no edge.
"""

from __future__ import annotations

import ast
import io
import os
import posixpath
import re
import tokenize
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

# Directory names never indexed: dependencies, vendored third-party code, virtualenvs,
# caches and VCS metadata.
DEFAULT_EXCLUDE_DIRS: tuple[str, ...] = (
    "node_modules", "vendor", "bower_components", ".git",
    "__pycache__", ".venv", "venv", "site-packages", "dist-packages",
    ".tox", ".mypy_cache", ".pytest_cache",
)

# Files larger than this are almost certainly bundled/minified, not app code.
MAX_FILE_BYTES = 512_000

# Template files searched for links to the app's URL routes (not parsed for imports).
TEMPLATE_EXTS: tuple[str, ...] = (
    ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".mustache", ".pug", ".jade", ".njk",
    ".jinja", ".jinja2", ".j2", ".twig", ".vue", ".erb",
)


@dataclass(frozen=True)
class ContextBudget:
    """Caps on the rendered context. An unbounded block would recreate the attention-dilution
    problem 3.6 addresses, so every section is capped and truncation is always marked."""
    max_importers: int = 5
    max_call_sites: int = 12      # per importer
    # When an importer uses the function/class around the findings, those lines are shown
    # plus at most this many of its other usage lines (e.g. unrelated routes in urls.py)
    max_other_call_sites: int = 3
    max_imports: int = 10
    max_chars: int = 4000
    max_line_chars: int = 160
    # URL routes section (its own cap, so importers can never push it out)
    max_routes: int = 6
    max_route_links: int = 4      # per route
    max_route_chars: int = 1500


# ---------------------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class ImportRef:
    """One import statement found in a file."""
    spec: str                     # "../data/user-dao", "express", ".models.Blogs", "yaml"
    line_no: int                  # 1-indexed line where the statement starts
    statement: str                # the statement, whitespace-collapsed, for display
    end_line: int                 # 1-indexed line where the statement ends
    bindings: tuple[str, ...]     # names bound at the import site (used to find call sites)
    is_local: bool                # relative import (./x, ../x, .x) vs package/absolute name
    # Tried when `spec` doesn't resolve. Python `from pkg import name` may import either the
    # submodule pkg/name.py (spec) or a name defined in pkg (alt_spec = "pkg").
    alt_spec: str | None = None


@dataclass
class _FileInfo:
    lines: list[str]              # original source lines
    code_lines: list[str]         # same lines with comments removed (line numbers aligned)
    refs: list[ImportRef] = field(default_factory=list)
    language: str = ""            # resolver language, e.g. "javascript" / "python"


@dataclass
class ImportIndex:
    app_root: Path
    files: dict[str, _FileInfo] = field(default_factory=dict)
    # file -> [(ref, resolved target or None)]
    imports: dict[str, list[tuple[ImportRef, str | None]]] = field(default_factory=dict)
    # target -> [(importer, ref)]
    importers: dict[str, list[tuple[str, ImportRef]]] = field(default_factory=dict)
    # package name -> [(file, ref)]
    package_usage: dict[str, list[tuple[str, ImportRef]]] = field(default_factory=dict)
    # template file -> lines (searched for links to URL routes; no imports)
    texts: dict[str, list[str]] = field(default_factory=dict)

    def language_of(self, path: str) -> str:
        info = self.files.get(path)
        return info.language if info else ""


class ImportResolver(Protocol):
    """Language-specific parsing. Add one per language and register it in RESOLVERS."""
    language: str
    extensions: tuple[str, ...]

    def strip_comments(self, text: str) -> str: ...
    def scan(self, code: str, original_lines: list[str]) -> list[ImportRef]: ...
    def prepare(self, files: set[str]) -> None: ...
    def resolve(self, from_file: str, spec: str, files: set[str]) -> str | None: ...
    def package_name(self, spec: str) -> str: ...
    def symbols_at(self, lines: list[str], line_nos: set[int]) -> set[str]: ...
    def defines(self, code: str, name: str) -> bool: ...
    def instance_pattern(self, binding: str) -> re.Pattern: ...


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------------------
# JavaScript / TypeScript resolver (CommonJS + ES modules)
# ---------------------------------------------------------------------------------------

_REQUIRE_RE = re.compile(r"""\brequire\(\s*["']([^"']+)["']\s*\)""")
_IDENT = r"[A-Za-z_$][\w$]*"
_DECL_SIMPLE_RE = re.compile(rf"(?:\bconst|\blet|\bvar)\s+({_IDENT})\s*=\s*$")
_DECL_DESTRUCT_RE = re.compile(r"(?:\bconst|\blet|\bvar)\s*\{([^{}]*)\}\s*=\s*$")
# `import X from "s"`, `import { a, b as c } from "s"`, `import * as ns from "s"`,
# `export { a } from "s"`, `export * from "s"` (clause may span lines)
_ESM_FROM_RE = re.compile(r"""\b(import|export)\s+((?:type\s+)?[^;'"`]*?)\s*\bfrom\s*["']([^"']+)["']""")
_ESM_BARE_RE = re.compile(r"""\bimport\s*["']([^"']+)["']""")          # import "s";
_ESM_DYNAMIC_RE = re.compile(r"""\bimport\(\s*["']([^"']+)["']\s*\)""")  # import("s")
_JS_EXTS = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx")
_JS_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "with", "else"}
_JS_DEF_RES = (
    re.compile(rf"\b(?:async\s+)?function\s*\*?\s*({_IDENT})\s*\("),
    re.compile(rf"\bclass\s+({_IDENT})\b"),
    re.compile(rf"\b(?:const|let|var)\s+({_IDENT})\s*=\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>|{_IDENT}\s*=>)"),
    re.compile(rf"\b(?:this|exports|module\.exports|self)\.({_IDENT})\s*=\s*(?:async\s+)?(?:function\b|\(|{_IDENT}\s*=>)"),
    re.compile(rf"^\s*(?:static\s+)?(?:async\s+)?({_IDENT})\s*\([^)]*\)\s*\{{"),
    re.compile(rf"^\s*({_IDENT})\s*:\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)"),
)


def _esm_bindings(clause: str) -> tuple[str, ...]:
    """Names bound by an ES import clause: default, `* as ns`, and `{ a, b as c }`."""
    clause = re.sub(r"^\s*type\s+", "", clause.strip())
    names: list[str] = []
    braces = re.search(r"\{([^{}]*)\}", clause)
    if braces:
        for part in braces.group(1).split(","):
            part = re.sub(r"^\s*type\s+", "", part.strip())
            if not part:
                continue
            name = part.split(" as ")[-1].strip()
            if re.fullmatch(_IDENT, name):
                names.append(name)
        clause = clause[:braces.start()] + clause[braces.end():]
    star = re.search(rf"\*\s*as\s+({_IDENT})", clause)
    if star:
        names.insert(0, star.group(1))
        clause = clause[:star.start()] + clause[star.end():]
    default = clause.strip().strip(",").strip()
    if re.fullmatch(_IDENT, default):
        names.insert(0, default)
    return tuple(names)


class JavaScriptResolver:
    language = "javascript"
    extensions = _JS_EXTS

    def strip_comments(self, text: str) -> str:
        """Remove // and /* */ comments, leaving string literals intact and keeping every
        newline so line numbers still match the original file. Regex literals are not
        recognised, so a regex containing a quote or // can confuse it -- acceptable for
        finding import statements."""
        out: list[str] = []
        i, n, quote = 0, len(text), None
        while i < n:
            c = text[i]
            if quote:
                out.append(c)
                if c == "\\" and i + 1 < n:
                    out.append(text[i + 1])
                    i += 2
                    continue
                if c == quote or (c == "\n" and quote != "`"):
                    quote = None
                i += 1
                continue
            if c in "\"'`":
                quote = c
                out.append(c)
                i += 1
                continue
            if text.startswith("//", i):
                j = text.find("\n", i)
                i = n if j == -1 else j
                continue
            if text.startswith("/*", i):
                j = text.find("*/", i + 2)
                end = n if j == -1 else j + 2
                out.append("\n" * text.count("\n", i, end))
                i = end
                continue
            out.append(c)
            i += 1
        return "".join(out)

    @staticmethod
    def _is_local(spec: str) -> bool:
        return spec.startswith("./") or spec.startswith("../")

    def _ref(self, code: str, lines: list[str], start: int, end: int, spec: str,
             bindings: tuple[str, ...]) -> ImportRef:
        start_line = code.count("\n", 0, start) + 1
        end_line = code.count("\n", 0, end) + 1
        return ImportRef(
            spec=spec, line_no=start_line,
            statement=_collapse(" ".join(lines[start_line - 1:end_line])),
            end_line=end_line, bindings=bindings, is_local=self._is_local(spec),
        )

    def scan(self, code: str, original_lines: list[str]) -> list[ImportRef]:
        refs: list[tuple[int, ImportRef]] = []
        for m in _REQUIRE_RE.finditer(code):
            spec = m.group(1)
            # The statement runs from the previous ';' (or start of file) to the require.
            boundary = code.rfind(";", 0, m.start())
            before = code[boundary + 1:m.start()]
            bindings: tuple[str, ...] = ()
            decl_offset = m.start()
            simple = _DECL_SIMPLE_RE.search(before)
            destruct = _DECL_DESTRUCT_RE.search(before)
            if simple:
                bindings = (simple.group(1),)
                decl_offset = boundary + 1 + simple.start()
            elif destruct:
                names = []
                for part in destruct.group(1).split(","):
                    part = part.strip()
                    if not part:
                        continue
                    # `{ a: b }` binds b; `{ a = 1 }` binds a
                    name = part.split(":")[-1].split("=")[0].strip()
                    if re.fullmatch(_IDENT, name):
                        names.append(name)
                bindings = tuple(names)
                decl_offset = boundary + 1 + destruct.start()
            elif re.search(rf"\bimport\s+({_IDENT})\s*=\s*$", before):     # TS import x = require()
                ts = re.search(rf"\bimport\s+({_IDENT})\s*=\s*$", before)
                bindings = (ts.group(1),)
                decl_offset = boundary + 1 + ts.start()
            refs.append((m.start(), self._ref(code, original_lines, decl_offset, m.end(), spec, bindings)))
        for m in _ESM_FROM_RE.finditer(code):
            kind, clause, spec = m.group(1), m.group(2), m.group(3)
            # `export { a } from "x"` re-exports: an edge, but binds nothing locally
            bindings = _esm_bindings(clause) if kind == "import" else ()
            refs.append((m.start(), self._ref(code, original_lines, m.start(), m.end(), spec, bindings)))
        for rx in (_ESM_BARE_RE, _ESM_DYNAMIC_RE):
            for m in rx.finditer(code):
                refs.append((m.start(), self._ref(code, original_lines, m.start(), m.end(), m.group(1), ())))
        refs.sort(key=lambda t: t[0])
        return [r for _, r in refs]

    def prepare(self, files: set[str]) -> None:
        return None

    def resolve(self, from_file: str, spec: str, files: set[str]) -> str | None:
        if not self._is_local(spec):
            return None
        base = posixpath.normpath(posixpath.join(posixpath.dirname(from_file), spec))
        cands = [base, *(base + e for e in _JS_EXTS), *(f"{base}/index{e}" for e in _JS_EXTS)]
        if base.endswith(".js"):                  # TypeScript ESM: "./x.js" means ./x.ts
            cands += [base[:-3] + ".ts", base[:-3] + ".tsx"]
        for cand in cands:
            if cand in files:
                return cand
        return None

    def package_name(self, spec: str) -> str:
        spec = spec[5:] if spec.startswith("node:") else spec
        parts = spec.split("/")
        return "/".join(parts[:2]) if spec.startswith("@") else parts[0]

    def symbols_at(self, lines: list[str], line_nos: set[int]) -> set[str]:
        """Name of the function/method/class each line sits in: the nearest definition at
        or above the line. Approximate, but enough to rank the caller lines that use it."""
        defs: list[tuple[int, str]] = []
        for i, line in enumerate(lines, start=1):
            for rx in _JS_DEF_RES:
                m = rx.search(line)
                if m and m.group(1) not in _JS_KEYWORDS:
                    defs.append((i, m.group(1)))
                    break
        out = set()
        for n in line_nos:
            above = [name for i, name in defs if i <= n]
            if above:
                out.add(above[-1])
        return out

    def defines(self, code: str, name: str) -> bool:
        m = re.escape(name)
        return re.search(
            rf"(?:\bthis\.{m}\s*=|\.{m}\s*=|\b{m}\s*:|\bfunction\s+{m}\b|"
            rf"\b(?:const|let|var|class)\s+{m}\b|(?:^|[\s,{{;]){m}\s*\([^)]*\)\s*\{{|"
            rf"module\.exports\s*=\s*\{{[^}}]*\b{m}\b|\bexport\s+(?:default\s+)?\{{[^}}]*\b{m}\b)",
            code, re.M,
        ) is not None

    def instance_pattern(self, binding: str) -> re.Pattern:
        # `const userDAO = new UserDAO(db)` -> userDAO
        return re.compile(rf"(?:\b(?:const|let|var)\s+|\bthis\.)({_IDENT})\s*=\s*new\s+{re.escape(binding)}\b")


# Backward-compatible name: the resolver started out as CommonJS-only.
CommonJSResolver = JavaScriptResolver


# ---------------------------------------------------------------------------------------
# Python resolver
# ---------------------------------------------------------------------------------------

_PY_IDENT = r"[A-Za-z_]\w*"
_DOTTED_RE = re.compile(rf"^{_PY_IDENT}(?:\.{_PY_IDENT})+$")
_MODULE_NAME_RE = re.compile(rf"^{_PY_IDENT}(?:\.{_PY_IDENT})*$")
# Calls whose first string argument names a module (Django URLconf include, importlib)
_MODULE_STRING_CALLS = {"include", "import_module", "import_string"}
_PY_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:from\s+(\.*[\w.]*)\s+import\s+(.+)|import\s+(.+))$"
)


def _py_join(module: str, name: str) -> str:
    """Module path for `from <module> import <name>`: '.' + 'views' -> '.views',
    'pkg' + 'mod' -> 'pkg.mod'."""
    return module + name if module.endswith(".") or not module else f"{module}.{name}"


class PythonResolver:
    language = "python"
    extensions = (".py",)

    def __init__(self) -> None:
        self._roots: tuple[str, ...] = ("",)

    def strip_comments(self, text: str) -> str:
        """Blank out `#` comments (via tokenize, so a '#' inside a string is kept), keeping
        every line so line numbers still match. Falls back to a simple line scan when the
        file doesn't tokenize (e.g. Python 2 code)."""
        lines = text.split("\n")
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    (row, col), (_, end) = tok.start, tok.end
                    line = lines[row - 1]
                    lines[row - 1] = line[:col] + line[end:]
            return "\n".join(lines)
        except (tokenize.TokenError, IndentationError, SyntaxError):
            out = []
            for line in text.split("\n"):
                hash_at = line.find("#")
                if hash_at != -1 and line.count('"', 0, hash_at) % 2 == 0 and line.count("'", 0, hash_at) % 2 == 0:
                    line = line[:hash_at].rstrip()
                out.append(line)
            return "\n".join(out)

    def _mk(self, lines: list[str], start: int, end: int, spec: str, bindings: tuple[str, ...],
            alt: str | None = None) -> ImportRef:
        return ImportRef(
            spec=spec, line_no=start,
            statement=_collapse(" ".join(lines[start - 1:end])),
            end_line=end, bindings=bindings, is_local=spec.startswith("."), alt_spec=alt,
        )

    def scan(self, code: str, original_lines: list[str]) -> list[ImportRef]:
        try:
            tree = ast.parse("\n".join(original_lines))
        except (SyntaxError, ValueError):
            return self._scan_regex(code, original_lines)
        refs: list[ImportRef] = []
        for node in ast.walk(tree):
            start = getattr(node, "lineno", 0)
            end = getattr(node, "end_lineno", start) or start
            if isinstance(node, ast.Import):
                for a in node.names:
                    binding = a.asname or a.name.split(".")[0]
                    refs.append(self._mk(original_lines, start, end, a.name, (binding,)))
            elif isinstance(node, ast.ImportFrom):
                module = "." * (node.level or 0) + (node.module or "")
                for a in node.names:
                    if a.name == "*":
                        refs.append(self._mk(original_lines, start, end, module, ()))
                    else:
                        refs.append(self._mk(original_lines, start, end, _py_join(module, a.name),
                                             (a.asname or a.name,), alt=module))
            elif isinstance(node, ast.Call) and node.args:
                func = node.func
                fname = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                arg = node.args[0]
                if (fname in _MODULE_STRING_CALLS and isinstance(arg, ast.Constant)
                        and isinstance(arg.value, str) and _DOTTED_RE.match(arg.value)):
                    refs.append(self._mk(original_lines, start, end, arg.value, (),
                                         alt=arg.value.rsplit(".", 1)[0]))
            elif isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id.isupper() for t in node.targets):
                # Django settings: ROOT_URLCONF = "proj.urls", WSGI_APPLICATION = "proj.wsgi.app",
                # and module lists such as INSTALLED_APPS = ["allauth", "shop.apps.ShopConfig"]
                if isinstance(node.value, ast.Constant):
                    value = node.value.value
                    if isinstance(value, str) and _DOTTED_RE.match(value):
                        refs.append(self._mk(original_lines, start, end, value, (),
                                             alt=value.rsplit(".", 1)[0]))
                elif isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        if (isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                                and _MODULE_NAME_RE.match(elt.value)):
                            line = getattr(elt, "lineno", start)
                            refs.append(self._mk(original_lines, line, line, elt.value, (),
                                                 alt=elt.value.rsplit(".", 1)[0] if "." in elt.value else None))
        refs.sort(key=lambda r: (r.line_no, r.spec))
        return refs

    def _scan_regex(self, code: str, original_lines: list[str]) -> list[ImportRef]:
        """Single-line import statements, for files `ast` can't parse."""
        refs: list[ImportRef] = []
        for i, line in enumerate(code.split("\n"), start=1):
            m = _PY_IMPORT_LINE_RE.match(line)
            if not m:
                continue
            if m.group(1) is not None:
                module, names = m.group(1), m.group(2).strip("() \\")
                for part in names.split(","):
                    bits = part.split(" as ")
                    name = bits[0].strip()
                    if name == "*":
                        refs.append(self._mk(original_lines, i, i, module, ()))
                    elif re.fullmatch(_PY_IDENT, name):
                        bound = bits[-1].strip()
                        refs.append(self._mk(original_lines, i, i, _py_join(module, name),
                                             (bound,), alt=module))
            else:
                for part in m.group(3).split(","):
                    bits = part.split(" as ")
                    name = bits[0].strip()
                    if re.fullmatch(rf"{_PY_IDENT}(?:\.{_PY_IDENT})*", name):
                        refs.append(self._mk(original_lines, i, i, name,
                                             (bits[-1].strip() if len(bits) > 1 else name.split(".")[0],)))
        return refs

    def prepare(self, files: set[str]) -> None:
        """Source roots for absolute imports: the app root, every folder holding a Django
        manage.py, and src/ (the common src-layout)."""
        roots = [""]
        roots += sorted({posixpath.dirname(f) for f in files
                         if posixpath.basename(f) == "manage.py" and posixpath.dirname(f)})
        if any(f.startswith("src/") for f in files):
            roots.append("src")
        self._roots = tuple(dict.fromkeys(roots))

    def resolve(self, from_file: str, spec: str, files: set[str]) -> str | None:
        level = len(spec) - len(spec.lstrip("."))
        parts = [p for p in spec[level:].split(".") if p]
        if level:
            base = posixpath.dirname(from_file)
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            bases = [base]
        else:
            if not parts:
                return None
            bases = list(self._roots)
        for b in bases:
            stem = posixpath.join(b, *parts) if parts else b
            for cand in (f"{stem}.py" if parts else None, posixpath.join(stem, "__init__.py") if stem else "__init__.py"):
                if cand and posixpath.normpath(cand) in files:
                    return posixpath.normpath(cand)
        return None

    def package_name(self, spec: str) -> str:
        return "" if spec.startswith(".") else spec.split(".")[0]

    def symbols_at(self, lines: list[str], line_nos: set[int]) -> set[str]:
        """Names of the functions/classes (innermost and enclosing) containing each line."""
        out: set[str] = set()
        try:
            tree = ast.parse("\n".join(lines))
        except (SyntaxError, ValueError):
            defs = [(i, m.group(1)) for i, line in enumerate(lines, start=1)
                    if (m := re.match(rf"\s*(?:async\s+)?(?:def|class)\s+({_PY_IDENT})", line))]
            for n in line_nos:
                above = [name for i, name in defs if i <= n]
                if above:
                    out.add(above[-1])
            return out
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                lo = min([node.lineno] + [d.lineno for d in node.decorator_list])
                hi = node.end_lineno or node.lineno
                if any(lo <= n <= hi for n in line_nos):
                    out.add(node.name)
        return out

    def defines(self, code: str, name: str) -> bool:
        m = re.escape(name)
        return re.search(
            rf"^\s*(?:async\s+)?def\s+{m}\b|^\s*class\s+{m}\b|^{m}\s*(?::[^=\n]*)?=|"
            rf"^\s*(?:from\s+\S+\s+)?import\s+.*\b{m}\b",
            code, re.M,
        ) is not None

    def instance_pattern(self, binding: str) -> re.Pattern:
        # `dao = UserDAO(db)` / `self.dao = UserDAO(db)` -> dao. Only for class-like
        # (CapWords) names: `result = check_vuln(x)` is a return value, not an instance.
        if not binding[:1].isupper():
            return re.compile(r"(?!x)x")
        return re.compile(rf"^\s*(?:self\.)?({_PY_IDENT})\s*=\s*{re.escape(binding)}\s*\(", re.M)


# Distribution names whose import name differs (requirements.txt name -> import name).
PY_DIST_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",), "pillow": ("PIL",), "beautifulsoup4": ("bs4",),
    "pyjwt": ("jwt",), "python-dateutil": ("dateutil",), "djangorestframework": ("rest_framework",),
    "django-heroku": ("django_heroku",), "psycopg2-binary": ("psycopg2",), "psycopg2": ("psycopg2",),
    "scikit-learn": ("sklearn",), "opencv-python": ("cv2",), "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",), "python-dotenv": ("dotenv",), "argon2-cffi": ("argon2",),
    "lxml": ("lxml",), "markupsafe": ("markupsafe",), "jinja2": ("jinja2",),
    "dnspython": ("dns",), "pyopenssl": ("OpenSSL",), "google-api-python-client": ("googleapiclient",),
    "msgpack-python": ("msgpack",), "attrs": ("attr", "attrs"), "setuptools": ("setuptools", "pkg_resources"),
    "django-allauth": ("allauth",), "django-cors-headers": ("corsheaders",),
    "django-crispy-forms": ("crispy_forms",), "django-environ": ("environ",),
    "django-filter": ("django_filters",), "social-auth-app-django": ("social_django",),
    "flask-sqlalchemy": ("flask_sqlalchemy",), "flask-login": ("flask_login",),
    "flask-cors": ("flask_cors",), "flask-wtf": ("flask_wtf",), "python-jose": ("jose",),
}


def python_import_names(dist: str) -> tuple[str, ...]:
    """Likely import names for a requirements.txt distribution name (PEP 503 normalised)."""
    norm = re.sub(r"[-_.]+", "-", dist.strip()).lower()
    if norm in PY_DIST_IMPORT_NAMES:
        return PY_DIST_IMPORT_NAMES[norm]
    return (norm.replace("-", "_"),)


RESOLVERS: list[ImportResolver] = [JavaScriptResolver(), PythonResolver()]


def resolver_for(path: str) -> ImportResolver | None:
    for r in RESOLVERS:
        if path.endswith(r.extensions):
            return r
    return None


_resolver_for = resolver_for  # older private name


def language_of_path(path: str) -> str:
    r = resolver_for(path)
    return r.language if r else ""


# ---------------------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------------------

def detect_app_language(app_root: str | Path) -> str:
    """"python" or "node" from the files at the app root ("" when it can't tell): a Django
    manage.py or a Python manifest without a package.json means Python."""
    root = Path(app_root)
    if not root.is_dir():
        return ""
    has = lambda name: (root / name).exists()  # noqa: E731
    if has("manage.py"):
        return "python"
    if has("package.json"):
        return "node"
    if any(has(n) for n in ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")):
        return "python"
    return ""


def detect_python_framework(app_root: str | Path) -> str:
    """"Django", "Flask", "FastAPI" or "" for a Python app, from manage.py or the declared
    requirements. Used only to name the app correctly in prompts."""
    root = Path(app_root)
    if (root / "manage.py").exists():
        return "Django"
    try:
        reqs = (root / "requirements.txt").read_text(encoding="utf-8", errors="replace").lower()
    except OSError:
        reqs = ""
    for name, label in (("django", "Django"), ("flask", "Flask"), ("fastapi", "FastAPI")):
        if re.search(rf"^\s*{name}\b", reqs, re.M):
            return label
    return ""


def app_root_for(repo_dir: str | Path, fix_path_prefix: str = "") -> Path:
    """Where app-relative batch paths (e.g. app/routes/x.js) live -- the same mapping
    gitops.git_gh_ops.repo_path applies."""
    root = Path(repo_dir)
    return root / fix_path_prefix if fix_path_prefix else root


def _merge_refs(pairs: list[tuple[ImportRef, str | None]]) -> list[tuple[ImportRef, str | None]]:
    """One entry per (statement line, target): `from .models import A, B` resolves both
    names to models.py, which should show once with bindings (A, B)."""
    merged: dict[tuple, tuple[ImportRef, str | None]] = {}
    for ref, target in pairs:
        key = (ref.line_no, target) if target else (ref.line_no, None, ref.spec)
        if key in merged:
            old, _ = merged[key]
            bindings = tuple(dict.fromkeys(old.bindings + ref.bindings))
            merged[key] = (replace(old, bindings=bindings), target)
        else:
            merged[key] = (ref, target)
    return list(merged.values())


def build_import_index(
    app_root: str | Path,
    exclude_dirs: tuple[str, ...] = DEFAULT_EXCLUDE_DIRS,
) -> ImportIndex:
    """Walk app_root once, parse every file a registered resolver understands, and build
    forward edges, reverse edges and package-usage sites. Keys are app-relative POSIX paths."""
    root = Path(app_root)
    index = ImportIndex(app_root=root)
    if not root.is_dir():
        return index

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in exclude_dirs)
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            resolver = resolver_for(rel)
            if resolver is None and name.lower().endswith(TEMPLATE_EXTS):
                try:
                    if full.stat().st_size <= MAX_FILE_BYTES:
                        index.texts[rel] = (full.read_text(encoding="utf-8", errors="replace")
                                            .replace("\r\n", "\n").split("\n"))
                except OSError:
                    pass
                continue
            if resolver is None or name.endswith((".min.js", ".bundle.js")):
                continue
            try:
                if full.stat().st_size > MAX_FILE_BYTES:
                    continue
                text = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            text = text.replace("\r\n", "\n")
            code = resolver.strip_comments(text)
            lines = text.split("\n")
            info = _FileInfo(lines=lines, code_lines=code.split("\n"), language=resolver.language)
            try:
                info.refs = resolver.scan(code, lines)
            except Exception:  # noqa: BLE001 -- one odd file must not sink the index
                info.refs = []
            index.files[rel] = info

    known = set(index.files)
    for r in RESOLVERS:
        r.prepare(known)
    for rel, info in index.files.items():
        resolver = resolver_for(rel)
        pairs: list[tuple[ImportRef, str | None]] = []
        for ref in info.refs:
            target = resolver.resolve(rel, ref.spec, known)
            if target is None and ref.alt_spec:
                target = resolver.resolve(rel, ref.alt_spec, known)
            pairs.append((ref, target if target != rel else None))
        pairs = _merge_refs(pairs)
        for ref, target in pairs:
            if target:
                index.importers.setdefault(target, []).append((rel, ref))
            elif not ref.is_local:
                pkg = resolver.package_name(ref.spec)
                if pkg:
                    index.package_usage.setdefault(pkg, []).append((rel, ref))
        index.imports[rel] = pairs
    return index


# ---------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------

def _clip(text: str, n: int) -> str:
    text = text.strip()
    return text if len(text) <= n else text[: n - 3] + "..."


def _tracked_names(info: _FileInfo, bindings: tuple[str, ...]) -> set[str]:
    """The imported names plus one level of instances made from them, e.g.
    `const userDAO = new UserDAO(db)` (or Python `dao = UserDAO(db)`) -> also track
    `userDAO`, since that is where the imported module's methods are actually called."""
    names = set(bindings)
    resolver = next((r for r in RESOLVERS if r.language == info.language), None) or RESOLVERS[0]
    code = "\n".join(info.code_lines)
    for b in bindings:
        names.update(m.group(1) for m in resolver.instance_pattern(b).finditer(code))
    return names


def _call_sites(
    info: _FileInfo,
    ref: ImportRef,
    budget: ContextBudget,
    focus: set[str] | frozenset[str] = frozenset(),
) -> tuple[list[str], int, int]:
    """Lines in an importer that use what it imported (excluding the import itself).
    Lines that mention a `focus` name (the function/class around the findings) come first,
    so the relevant caller survives the cap even in a large file such as a Django urls.py.
    Returns (lines shown, lines not shown, number of focus lines)."""
    names = _tracked_names(info, ref.bindings)
    if not names:
        return [], 0, 0
    pat = re.compile(r"(?<![\w$])(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\b")
    # A focus use is `<imported name>.<focus>` (views.sql_lab, profileHandler.displayProfile)
    # or a focus name imported directly (`from .views import sql_lab`), never a mere string
    # such as path("sql_lab", ...).
    focus_pat = None
    if focus:
        alts = [rf"(?:{'|'.join(re.escape(n) for n in sorted(names))})\s*\.\s*(?:{'|'.join(re.escape(f) for f in sorted(focus))})\b"]
        direct = sorted(focus & set(ref.bindings))
        if direct:
            alts.append(r"(?<![\w$.\'\"])(?:" + "|".join(re.escape(f) for f in direct) + r")\b")
        focus_pat = re.compile("|".join(alts))
    # Skip import statements (this one and any other: `from django.contrib.auth import
    # login` is not a use of a model named `login`)
    stmt_lines = {n for r in info.refs for n in range(r.line_no, r.end_line + 1)}
    stmt_lines |= set(range(ref.line_no, ref.end_line + 1))
    first, rest = [], []
    for i, code_line in enumerate(info.code_lines, start=1):
        if i in stmt_lines or not pat.search(code_line):
            continue
        hit = f"L{i}: {_clip(info.lines[i - 1], budget.max_line_chars)}"
        (first if focus_pat and focus_pat.search(code_line) else rest).append(hit)
    found = len(first) + len(rest)
    if first:
        rest = rest[: budget.max_other_call_sites]
    shown = (first + rest)[: budget.max_call_sites]
    hidden = found - len(shown)
    return shown, max(0, hidden), len(first)


def focus_symbols(file_path: str, findings: list[dict] | None, index: ImportIndex | None) -> set[str]:
    """Names of the functions/classes in `file_path` that contain a finding's line."""
    if index is None or not findings:
        return set()
    path = posixpath.normpath(file_path.replace("\\", "/"))
    info = index.files.get(path)
    resolver = resolver_for(path)
    if info is None or resolver is None:
        return set()
    lines = {(f.get("location") or {}).get("line") for f in findings}
    lines = {n for n in lines if isinstance(n, int) and n > 0}
    return resolver.symbols_at(info.lines, lines) if lines else set()


def gather_repo_context(
    file_path: str,
    index: ImportIndex | None,
    budget: ContextBudget = ContextBudget(),
    findings: list[dict] | None = None,
) -> str:
    """Render how `file_path` (app-relative) is used elsewhere in the app, within budget.
    With `findings`, importers and caller lines that use the function/class containing a
    finding are listed first. Returns "" when there is nothing to say, so the prompt gains
    no empty section."""
    if index is None:
        return ""
    path = posixpath.normpath(file_path.replace("\\", "/"))
    if path not in index.files:
        return ""

    out: list[str] = []
    focus = focus_symbols(path, findings, index)

    importers = sorted(index.importers.get(path, []), key=lambda t: (t[0], t[1].line_no))
    if importers:
        # One entry per importing file, even when it imports this file in several statements
        # (`import auth` and `from auth import verify_token`)
        groups: dict[str, list] = {}
        for importer, ref in importers:
            sites, more, n_focus = _call_sites(index.files[importer], ref, budget, focus)
            uses_focus = n_focus > 0 or bool(focus & set(ref.bindings))
            groups.setdefault(importer, []).append((uses_focus, ref, sites, more))
        rendered = [(not any(e[0] for e in entries), importer, entries)
                    for importer, entries in groups.items()]
        if focus:
            rendered.sort(key=lambda t: (t[0], t[1]))
        if focus and any(not t[0] for t in rendered):
            names = ", ".join(sorted(focus))
            out.append("Imported by (these files depend on this file -- keep them working; lines "
                       f"using {names}, which contains the findings, are listed first):")
        else:
            out.append("Imported by (these files depend on this file -- keep them working):")
        for _, importer, entries in rendered[: budget.max_importers]:
            out.append(f"- {importer}")
            if focus:
                entries = sorted(entries, key=lambda e: not e[0])
            for _, ref, sites, more in entries:
                out.append(f"    L{ref.line_no}: {_clip(ref.statement, budget.max_line_chars)}")
                out.extend(f"    {s}" for s in sites)
                if more:
                    out.append(f"    ... ({more} more usage line(s) not shown)")
        if len(rendered) > budget.max_importers:
            out.append(f"... ({len(rendered) - budget.max_importers} more importer(s) not shown)")

    local_imports = [(ref, tgt) for ref, tgt in index.imports.get(path, []) if tgt]
    if local_imports:
        if out:
            out.append("")
        out.append("Imports (local modules this file depends on):")
        for ref, tgt in local_imports[: budget.max_imports]:
            out.append(f"- {tgt} via L{ref.line_no}: {_clip(ref.statement, budget.max_line_chars)}")
        if len(local_imports) > budget.max_imports:
            out.append(f"... ({len(local_imports) - budget.max_imports} more import(s) not shown)")

    routes = render_route_links(path, index, budget, focus)
    if not out:
        return routes

    text = "\n".join(out)
    if len(text) > budget.max_chars:
        marker = "\n... (truncated)"
        text = text[: budget.max_chars - len(marker)].rsplit("\n", 1)[0] + marker
    return f"{routes}\n\n{text}" if routes else text


# ---------------------------------------------------------------------------------------
# URL routes and the links to them (templates are not imports, so the import graph alone
# never shows that views/layout.html links to /allocations/{{userId}})
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    method: str        # GET / POST / ANY for Express, URL for Django, ROUTE for Flask
    path: str          # full URL path as registered, e.g. /allocations/:userId
    prefix: str        # static part before the first parameter, e.g. /allocations
    has_param: bool
    name: str          # Django url name ("" when none)
    file: str          # where it is registered
    line_no: int
    statement: str
    focus: bool        # the line names the function/class that contains a finding


_JS_ROUTE_RE = re.compile(r"""\.(get|post|put|patch|delete|all|route)\s*\(\s*(["'`])(/[^"'`$]*)\2""")
_JS_MOUNT_RE = re.compile(r"""\.use\s*\(\s*(["'`])(/[^"'`$]*)\1\s*,(.*)""")
_PY_ROUTE_RE = re.compile(r"""\b(re_path|path|url)\s*\(\s*r?(["'])([^"']*)\2\s*,(.*)""")
_PY_ROUTE_NAME_RE = re.compile(r"""\bname\s*=\s*["']([\w\-:.]+)["']""")
_FLASK_ROUTE_RE = re.compile(r"""@\s*[\w.]+\.(route|get|post|put|patch|delete)\s*\(\s*r?["']([^"']*)["']""")
_PARAM_START_RE = re.compile(r"[:<(*\[\\?$+]")


def _route_prefix(path: str, regex: bool = False) -> tuple[str, str, bool]:
    """(display path, static prefix, has parameter) with a leading slash and no trailing one."""
    raw = path.lstrip("^").rstrip("$") if regex else path
    m = _PARAM_START_RE.search(raw)
    static = raw[: m.start()] if m else raw
    display = "/" + raw.lstrip("/")
    prefix = "/" + static.strip("/") if static.strip("/") else ""
    return display, prefix, bool(m)


def _join_url(mount: str, path: str) -> str:
    if not mount:
        return path
    return mount.rstrip("/") + ("" if path in ("", "/") else "/" + path.lstrip("/")) or "/"


def _parse_route(line: str, language: str) -> list[tuple[str, str, bool, str]]:
    """Routes registered on one code line: [(method, path, is_regex, url name)]."""
    found = []
    if language == "javascript":
        for m in _JS_ROUTE_RE.finditer(line):
            method = m.group(1).upper()
            found.append(("ANY" if method in ("ALL", "ROUTE") else method, m.group(3), False, ""))
    elif language == "python":
        m = _PY_ROUTE_RE.search(line)
        if m and "include(" not in m.group(4):
            name = _PY_ROUTE_NAME_RE.search(m.group(4))
            found.append(("URL", m.group(3), m.group(1) != "path", name.group(1) if name else ""))
        for m in _FLASK_ROUTE_RE.finditer(line):
            found.append(("ROUTE", m.group(2), False, ""))
    return found


def _names_pattern(names: set[str]) -> re.Pattern | None:
    if not names:
        return None
    return re.compile(r"(?<![\w$.])(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\b")


def _mount_prefixes(path: str, index: ImportIndex) -> list[str]:
    """URL prefixes a file's routes are mounted under: Express `app.use("/tutorial", router)`
    or Django `path("challenge/", include("challenge.urls"))` in a file importing it."""
    prefixes: list[str] = []
    for importer, ref in index.importers.get(path, []):
        info = index.files[importer]
        if info.language == "python":
            m = _PY_ROUTE_RE.search(info.code_lines[ref.line_no - 1]) if ref.line_no <= len(info.code_lines) else None
            if m and "include(" in m.group(4):
                prefixes.append("/" + m.group(3).strip("/") if m.group(3).strip("/") else "")
            continue
        names = _names_pattern(_tracked_names(info, ref.bindings))
        if names is None:
            continue
        for line in info.code_lines:
            m = _JS_MOUNT_RE.search(line)
            if m and names.search(m.group(3)):
                prefixes.append(m.group(2) if m.group(2) != "/" else "")
    return list(dict.fromkeys(prefixes)) or [""]


def routes_for_file(path: str, index: ImportIndex, focus: set[str] | frozenset[str] = frozenset()) -> list[Route]:
    """URL routes `path` serves: registered in the file itself, or registered in a file that
    imports it and points the route at what it imported (index.js -> allocationsHandler,
    urls.py -> views.sql_lab). Mount prefixes are applied one level up."""
    path = posixpath.normpath(path.replace("\\", "/"))
    info = index.files.get(path)
    if info is None:
        return []
    routes: list[Route] = []

    def add(file: str, line_no: int, mounts: list[str], is_focus: bool) -> None:
        f_info = index.files[file]
        for method, raw, regex, name in _parse_route(f_info.code_lines[line_no - 1], f_info.language):
            for mount in mounts:
                display, prefix, has_param = _route_prefix(_join_url(mount, raw) if not regex else raw, regex)
                if regex and mount:
                    display, prefix = _join_url(mount, display), _join_url(mount, prefix)
                routes.append(Route(method, display, prefix, has_param, name, file, line_no,
                                    _collapse(f_info.lines[line_no - 1]), is_focus))

    focus_any = _names_pattern(set(focus))
    own_mounts = _mount_prefixes(path, index)
    for i, line in enumerate(info.code_lines, start=1):
        if _parse_route(line, info.language):
            add(path, i, own_mounts, bool(focus_any and focus_any.search(line)))
    # Flask: a decorator's focus is the function defined right below it
    for importer, ref in index.importers.get(path, []):
        imp = index.files[importer]
        names = _tracked_names(imp, ref.bindings)
        pat = _names_pattern(names)
        if pat is None:
            continue
        focus_pat = None
        if focus:
            focus_pat = re.compile(
                r"(?:" + "|".join(re.escape(n) for n in sorted(names)) + r")\s*\.\s*(?:"
                + "|".join(re.escape(f) for f in sorted(focus)) + r")\b"
                + (r"|(?<![\w$.'\"])(?:" + "|".join(re.escape(f) for f in sorted(set(focus) & set(ref.bindings))) + r")\b"
                   if set(focus) & set(ref.bindings) else ""))
        mounts = None
        for i, line in enumerate(imp.code_lines, start=1):
            if not pat.search(line) or not _parse_route(line, imp.language):
                continue
            if mounts is None:
                mounts = _mount_prefixes(importer, index)
            add(importer, i, mounts, bool(focus_pat and focus_pat.search(line)))
    return list(dict.fromkeys(routes))


def _link_pattern(route: Route) -> re.Pattern | None:
    alts = []
    if route.prefix:
        after = r"/" if route.has_param else r"/?(?=$|[\"'?#\s<`)\]},;])"
        alts.append(r"(?<![\w/.\-])" + re.escape(route.prefix) + after)
    if route.name:
        n = re.escape(route.name)
        alts.append(rf"\{{%-?\s*url\s+[\"']{n}[\"']")
        alts.append(rf"\b(?:reverse|reverse_lazy|redirect|url_for)\s*\(\s*[\"']{n}[\"']")
    return re.compile("|".join(alts)) if alts else None


def route_links(route: Route, index: ImportIndex, registrations: set[tuple[str, int]]) -> list[tuple[str, int, str]]:
    """Template and code lines that link to `route`, as (file, line number, line)."""
    pat = _link_pattern(route)
    if pat is None:
        return []
    hits = []
    sources = [(f, lines, lines) for f, lines in sorted(index.texts.items())]
    sources += [(f, info.lines, info.code_lines) for f, info in sorted(index.files.items())]
    for file, lines, search_lines in sources:
        for i, line in enumerate(search_lines, start=1):
            if (file, i) in registrations or not pat.search(line):
                continue
            hits.append((file, i, lines[i - 1]))
    return hits


def render_route_links(
    file_path: str,
    index: ImportIndex | None,
    budget: ContextBudget = ContextBudget(),
    focus: set[str] | frozenset[str] = frozenset(),
) -> str:
    """The URL routes this file serves that other parts of the app link to, with the linking
    lines. Only routes a fix could break for those links are shown: routes with a parameter
    (the IDOR fix that turned /allocations/:userId into /allocations broke the menu link
    /allocations/{{userId}}), and parameterless routes whose handler contains a finding.
    Routes with no link are left out. Returns "" when there is nothing to say."""
    if index is None:
        return ""
    routes = [r for r in routes_for_file(file_path, index, focus) if r.has_param or r.focus]
    if not routes:
        return ""
    registrations: set[tuple[str, int]] = set()
    for f, info in index.files.items():
        for i, line in enumerate(info.code_lines, start=1):
            if _parse_route(line, info.language) or _JS_MOUNT_RE.search(line):
                registrations.add((f, i))
    linked = []
    for r in routes:
        links = route_links(r, index, registrations)
        if links:
            linked.append((r, links))
    if not linked:
        return ""
    linked.sort(key=lambda t: (not t[0].focus, not t[0].has_param, t[0].file, t[0].line_no))
    out = ["URL routes this file serves, and where the app links to them. Keep these URLs, "
           "including their parameters, working for these links; if a parameter must no longer "
           "be trusted, keep accepting it and stop using it rather than removing it:"]
    for r, links in linked[: budget.max_routes]:
        where = f"{r.file} L{r.line_no}: {_clip(r.statement, budget.max_line_chars)}"
        out.append(f"- {r.method} {r.path}" + (f" (name '{r.name}')" if r.name else "")
                   + f", registered at {where}")
        for file, line_no, line in links[: budget.max_route_links]:
            out.append(f"    {file} L{line_no}: {_clip(line, budget.max_line_chars)}")
        if len(links) > budget.max_route_links:
            out.append(f"    ... ({len(links) - budget.max_route_links} more link(s) not shown)")
    if len(linked) > budget.max_routes:
        out.append(f"... ({len(linked) - budget.max_routes} more linked route(s) not shown)")
    text = "\n".join(out)
    if len(text) > budget.max_route_chars:
        marker = "\n... (truncated)"
        text = text[: budget.max_route_chars - len(marker)].rsplit("\n", 1)[0] + marker
    return text


def package_usage_sites(index: ImportIndex | None, package: str) -> list[str]:
    """`file:line` locations where a third-party package is imported, for review notes."""
    if index is None:
        return []
    sites = [f"{f}:{ref.line_no}" for f, ref in sorted(
        index.package_usage.get(package, []), key=lambda t: (t[0], t[1].line_no)
    )]
    return list(dict.fromkeys(sites))   # `from PIL import Image, ImageMath` is one site


# ---------------------------------------------------------------------------------------
# SAST code flow (scanner-reported data flow, source to sink)
# ---------------------------------------------------------------------------------------

LIBRARY_DIRS = ("node_modules/", "vendor/", "bower_components/", "site-packages/",
                "dist-packages/", ".venv/", "venv/")


def _is_library(path: str) -> bool:
    p = path.replace("\\", "/")
    return any(p.startswith(d) or f"/{d}" in p for d in LIBRARY_DIRS)


def _source_lines(path: str, index: ImportIndex | None, app_root: Path | None) -> list[str]:
    if index is not None and path in index.files:
        return index.files[path].lines
    root = app_root or (index.app_root if index is not None else None)
    if root is None:
        return []
    try:
        return (Path(root) / path).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")
    except OSError:
        return []


def render_code_flow(
    file_path: str,
    findings: list[dict],
    index: ImportIndex | None,
    *,
    app_root: Path | None = None,
    max_chars: int = 2000,
    context_lines: int = 2,
    max_line_chars: int = 160,
) -> str:
    """Render the scanner's data flow for this file's findings (from the normaliser's
    `code_flow`): the source-to-sink path through this file, and the code at each step in
    OTHER files on the path -- the "files in codeflow" that ITP2 task 1 asks to include.
    Library code (node_modules etc.) is excluded. A flow that never leaves its sink line
    adds nothing and is skipped. Returns "" when there is nothing to show."""
    this = posixpath.normpath(file_path.replace("\\", "/"))
    own_lines = _source_lines(this, index, app_root)
    paths: list[str] = []
    others: dict[str, set[int]] = {}

    for f in findings:
        steps = [s for s in (f.get("code_flow") or []) if s.get("file") and not _is_library(s["file"])]
        if len({(s["file"], s.get("line")) for s in steps}) < 2:
            continue
        hops = []
        for s in steps:
            step_file = posixpath.normpath(s["file"].replace("\\", "/"))
            line = s.get("line")
            if step_file == this:
                hops.append(f"L{line}")
            else:
                hops.append(f"{step_file} L{line}")
                if isinstance(line, int):
                    others.setdefault(step_file, set()).add(line)
        title = f.get("title") or (f.get("identifiers") or {}).get("rule_id") or "finding"
        sink = (f.get("location") or {}).get("line")
        paths.append(f"- {title} (line {sink}): " + " -> ".join(hops))
        for s in steps:
            if posixpath.normpath(s["file"].replace("\\", "/")) == this and isinstance(s.get("line"), int):
                n = s["line"]
                if 1 <= n <= len(own_lines):
                    paths.append(f"    L{n}: {_clip(own_lines[n - 1], max_line_chars)}")

    if not paths:
        return ""
    out = ["Data flow reported by the SAST scanner for this file's findings:", *paths]
    if others:
        out.append("")
        out.append("Other files in the data flow (read-only; libraries excluded):")
        for other, lines in sorted(others.items()):
            src = _source_lines(other, index, app_root)
            out.append(f"- {other}")
            shown: set[int] = set()
            for n in sorted(lines):
                for k in range(max(1, n - context_lines), min(len(src), n + context_lines) + 1):
                    if k not in shown:
                        shown.add(k)
                        out.append(f"    L{k}: {_clip(src[k - 1], max_line_chars)}")

    text = "\n".join(out)
    if len(text) > max_chars:
        marker = "\n... (truncated)"
        text = text[: max_chars - len(marker)].rsplit("\n", 1)[0] + marker
    return text

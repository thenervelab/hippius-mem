#!/usr/bin/env python3
"""Verify relative markdown links across all git-tracked *.md files.

For every relative link the target file must exist; a `#anchor` must match the
GitHub slug of some heading in the target. External links (http/https/mailto)
are skipped — no network. Exits non-zero listing breaks as `file:line: link -> reason`.

Scope: inline links and ATX headings only — reference-style links, setext
headings, and link text containing backticks are unchecked.
"""

import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

# Inline link/image: [text](target) or ![alt](target "title"). Target may be <wrapped>.
LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)<>\s]+)>?(?:\s+[\"'][^\"']*[\"'])?\s*\)")
HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*#*\s*$")
FENCE_RE = re.compile(r"^\s{0,3}(```|~~~)")
CODE_SPAN_RE = re.compile(r"`[^`]*`")
EXTERNAL_RE = re.compile(r"^(https?:|mailto:)", re.IGNORECASE)


def tracked_markdown_files(repo_root: Path) -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z", "*.md"],
        cwd=repo_root, capture_output=True, text=True, check=True,
    ).stdout
    return [repo_root / name for name in out.split("\0") if name]


def body_lines(path: Path) -> list[tuple[int, str]]:
    """(line_number, text) pairs with fenced code blocks blanked out."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        print(f"{path}: not valid UTF-8", file=sys.stderr)
        sys.exit(1)
    lines = []
    in_fence = False
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append((lineno, raw))
    return lines


def github_slug(heading: str, seen: dict[str, int]) -> str:
    # Render-ish pass: keep link text, drop the URL part, before slugging.
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    # GitHub slugger rules (source: the `github-slugger` npm package, which
    # GitHub uses): lowercase, strip punctuation (em-dashes vanish, so the
    # spaces around " — " collapse to "--"), then spaces become hyphens.
    text = re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")
    # Our -N dedup keys on the base slug text; github-slugger keys on each
    # emitted slug, so headings "A", "A", "A-1" diverge (theoretical here).
    n = seen.get(text, 0)
    seen[text] = n + 1
    return text if n == 0 else f"{text}-{n}"


def heading_slugs(path: Path, cache: dict[Path, set[str]]) -> set[str]:
    if path not in cache:
        seen: dict[str, int] = {}
        slugs = set()
        for _, line in body_lines(path):
            m = HEADING_RE.match(line)
            if m:
                slugs.add(github_slug(m.group(1), seen))
        cache[path] = slugs
    return cache[path]


def check_link(
    source: Path, target: str, repo_root: Path, cache: dict[Path, set[str]]
) -> str | None:
    """Return a failure reason, or None if the link resolves."""
    path_part, _, anchor = target.partition("#")
    path_part = unquote(path_part)
    if not path_part:
        dest = source
    elif path_part.startswith("/"):
        dest = repo_root / path_part.lstrip("/")
    else:
        dest = (source.parent / path_part).resolve()
    if not dest.exists():
        return f"target file not found: {path_part}"
    if anchor and dest.suffix.lower() == ".md":
        # Exact match: GitHub fragments are case-sensitive, and slugs are always
        # lowercase — an uppercase anchor is broken even if the heading exists.
        if anchor not in heading_slugs(dest, cache):
            # A ../.. link can resolve outside the repo; fall back to the
            # absolute path rather than crashing on relative_to.
            try:
                shown = dest.relative_to(repo_root)
            except ValueError:
                shown = dest
            return f"no heading with slug #{anchor} in {shown}"
    return None


def main() -> int:
    try:
        # Resolve once so relative_to() agrees with the resolved link targets
        # (macOS symlinks /var -> /private/var, which would otherwise mismatch).
        repo_root = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, check=True,
            ).stdout.strip()
        ).resolve()
        markdown_files = tracked_markdown_files(repo_root)
    except subprocess.CalledProcessError as err:
        # Default __str__ hides the captured stderr; surface git's message.
        sys.stderr.write(err.stderr or "")
        print(f"git command failed: {err}", file=sys.stderr)
        return 1
    slug_cache: dict[Path, set[str]] = {}
    failures = []
    checked = 0
    for md in markdown_files:
        for lineno, line in body_lines(md):
            for m in LINK_RE.finditer(CODE_SPAN_RE.sub("", line)):
                target = m.group(1)
                if EXTERNAL_RE.match(target):
                    continue
                checked += 1
                reason = check_link(md, target, repo_root, slug_cache)
                if reason:
                    rel = md.relative_to(repo_root)
                    failures.append(f"{rel}:{lineno}: {target} -> {reason}")
    for failure in failures:
        print(failure)
    print(f"{checked - len(failures)}/{checked} relative links OK", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

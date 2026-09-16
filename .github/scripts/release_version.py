"""Validate a release tag against this checkout before building or publishing."""

import pathlib
import re
import sys
import xml.etree.ElementTree as ET


def release_version(tag: str, root: pathlib.Path) -> tuple[str, bool]:
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)\.[1-9][0-9]*)?", tag):
        raise ValueError("Use vX.Y.Z or vX.Y.Z-{alpha,beta,rc}.N for release tags")
    version = tag[1:]
    pom = ET.parse(root / "pom.xml")
    project_version = pom.getroot().findtext("{http://maven.apache.org/POM/4.0.0}version")
    if project_version != version:
        raise ValueError(f"Tag version {version} does not match pom.xml version {project_version}")
    notes = root / "docs" / "releases" / f"{version}.md"
    if not notes.is_file() or not notes.read_text(encoding="utf-8").strip():
        raise ValueError(f"Missing release notes: {notes}")
    return version, "-" in version


if __name__ == "__main__":
    try:
        version, prerelease = release_version(sys.argv[1], pathlib.Path.cwd())
    except (IndexError, ValueError) as exc:
        sys.exit(str(exc))
    print(f"version={version}")
    print(f"prerelease={str(prerelease).lower()}")

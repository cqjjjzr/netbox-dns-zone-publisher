#!/usr/bin/env python3
"""Include dependency license declarations and upstream notices in the binary deb."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--frozen", "--format-version=1"], text=True
))
destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
for package in metadata["packages"]:
    if package["source"] is None:
        continue
    root = Path(package["manifest_path"]).parent
    target = destination / f'{package["name"]}-{package["version"]}'
    target.mkdir(exist_ok=True)
    (target / "copyright").write_text(
        f'Crate: {package["name"]}\nVersion: {package["version"]}\n'
        f'Source: {package["source"]}\n'
        f'License: {package["license"] or "See license file"}\n'
        f'Authors: {", ".join(package["authors"])}\n'
    )
    notices = [p for p in root.iterdir() if p.name.lower().startswith(
        ("license", "licence", "copying", "copyright", "notice"))]
    if package["license_file"]:
        notices.append(root / package["license_file"])
    for notice in set(notices):
        if notice.is_dir():
            shutil.copytree(notice, target / notice.name, dirs_exist_ok=True)
        else:
            shutil.copy2(notice, target / notice.name)

# Cargo archives sometimes use epoch timestamps; keep package dates reproducible.
epoch = int(os.environ["SOURCE_DATE_EPOCH"])
for path in [destination, *destination.rglob("*")]:
    os.utime(path, (epoch, epoch))

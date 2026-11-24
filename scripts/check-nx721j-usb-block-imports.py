#!/usr/bin/env python3
"""Report USB block driver imports that still need a kernel link binding."""

import argparse
from pathlib import Path
import re
import subprocess


STORAGE_SYMBOL = re.compile(r"__(?:ZNK?20IOBlockStorageDevice|ZTV20IOBlockStorageDevice)")


def symbols(path: Path, *options: str) -> set[str]:
    output = subprocess.check_output(
        ["llvm-nm", "--just-symbol-name", *options, str(path)], text=True
    )
    return set(output.splitlines())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object", type=Path)
    parser.add_argument("kernel", type=Path)
    args = parser.parse_args()

    imports = symbols(args.object, "--undefined-only")
    definitions = symbols(args.kernel, "--defined-only", "--extern-only")
    missing = imports - definitions
    storage = {name for name in missing if STORAGE_SYMBOL.match(name)}
    unexpected = missing - storage

    print(f"USB block driver imports: {len(imports)}")
    print(f"Defined by kernel symbol table: {len(imports & definitions)}")
    print(f"IOStorageFamily imports needing bindings: {len(storage)}")
    for name in sorted(storage):
        print(f"  {name}")
    print(f"Unexpected unresolved imports: {len(unexpected)}")
    for name in sorted(unexpected):
        print(f"  {name}")
    return int(bool(unexpected))


if __name__ == "__main__":
    raise SystemExit(main())

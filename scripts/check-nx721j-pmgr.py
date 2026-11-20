#!/usr/bin/env python3
"""Check the prelinked AMFI and PMGR ABI in the NX721J 21H461 build."""

import argparse
import hashlib
import json
from pathlib import Path
import struct


REFERENCE_SHA256 = "f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7"
MODULES = {
    "com.apple.driver.AppleMobileFileIntegrity":
        "a1088aaabc259418ed503d08df29b6146470b8c962696c688122a1f60a141db6",
    "com.apple.driver.ApplePMGR":
        "2c433279d004803b7ef02948e550ad6b77aa3f84b02a06a357e00fa738310a99",
}
# Virtual addresses for the 21H461 prelink layout recorded in board.toml.
AMFI_MATCH_CLASS = 0xFFFFFFF0042DDE02
AMFI_PMGRAON = 0xFFFFFFF004AAEB40
NUB_READ = 0xFFFFFFF004A24ADC
NUB_WRITE = 0xFFFFFFF004A230EC
PROVIDER_VTABLE = 0xFFFFFFF005CE26D8
BASE_READ = 0xFFFFFFF004A20FBC
BASE_WRITE = 0xFFFFFFF004A20FC4


def require(ok, message):
    if not ok:
        raise SystemExit(message)


def segments(image):
    require(len(image) >= 32, "Truncated Mach-O header")
    magic, cpu, _, _, count, size, _, _ = struct.unpack_from("<8I", image)
    end = 32 + size
    require(magic == 0xFEEDFACF and cpu == 0x0100000C and end <= len(image),
            "Expected an ARM64 Mach-O with a complete load command table")
    at = 32
    for _ in range(count):
        require(at + 8 <= end, "Truncated Mach-O load command")
        command, length = struct.unpack_from("<II", image, at)
        require(8 <= length <= end - at, "Invalid Mach-O load command length")
        if command == 0x19:
            require(length >= 72, "Truncated Mach-O segment command")
            va, vm_size, offset, file_size = struct.unpack_from("<4Q", image, at + 24)
            require(file_size <= vm_size and offset + file_size <= len(image),
                    "Invalid Mach-O segment extent")
            yield va, offset, file_size
        at += length
    require(at == end, "Unexpected bytes in Mach-O load command table")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel", type=Path, help="CI kernel.macho with its sibling kernel.json")
    args = parser.parse_args()
    image = args.kernel.read_bytes()
    manifest = json.loads(args.kernel.with_suffix(".json").read_text(encoding="utf-8"))
    require(manifest["original_sha256"] == REFERENCE_SHA256, "Unexpected prelink reference")
    require(hashlib.sha256(image).hexdigest() == manifest["candidate_sha256"],
            "Kernel differs from the CI manifest")
    layout = tuple(segments(image))

    def read(va, size):
        for base, offset, length in layout:
            if base <= va and va + size <= base + length:
                start = offset + va - base
                return image[start:start + size]
        raise SystemExit(f"Range {va:#x}+{size:#x} is not file-backed")

    for module, digest in MODULES.items():
        extents = [entry for entry in manifest["extents"] if
                   entry["module"] == module and entry["segment"] == "__TEXT_EXEC"]
        require(len(extents) == 1, f"Expected one executable extent for {module}")
        extent = extents[0]
        actual = hashlib.sha256(read(extent["va"], extent["size"])).hexdigest()
        require(actual == manifest["original_executable_sha256"][module] == digest,
                f"Unexpected executable digest for {module}")

    def check_words(va, *words):
        expected = struct.pack("<" + "I" * len(words), *words)
        require(read(va, len(expected)) == expected, f"Instruction mismatch at {va:#x}")

    require(read(AMFI_MATCH_CLASS, 13) == b"ApplePMGRNub\0", "AMFI matching class differs")
    check_words(AMFI_PMGRAON, 0x94006C46, 0x321E0015, 0xAA1403E0, 0xAA1503E1, 0x94006C45)
    check_words(NUB_READ, 0xF9404400, 0xB4000080, 0xF9400008, 0xF9450101,
                0xD61F0020, 0x12800000, 0xD65F03C0)
    check_words(NUB_WRITE, 0xF9404400, 0xB4000080, 0xF9400008, 0xF9450502,
                0xD61F0040, 0xD65F03C0)
    require(struct.unpack("<2Q", read(PROVIDER_VTABLE + 320 * 8, 16)) == (BASE_READ, BASE_WRITE),
            "Unexpected ApplePMGR base provider slots")
    check_words(BASE_READ, 0x12800000, 0xD65F03C0)
    check_words(BASE_WRITE, 0xD65F03C0)
    print("PASS: original AMFI and ApplePMGR executable bytes")
    print("PASS: ApplePMGRNub matching and AON provider slots 320 and 321")


if __name__ == "__main__":
    main()

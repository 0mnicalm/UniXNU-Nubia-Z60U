#!/usr/bin/env python3
"""Compare the compiled USB block class with the NX721J prelinked storage ABI."""

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys


BUNDLE = "com.apple.iokit.IOStorageFamily"
ABI_SLOTS = 190


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def driver_table(obj, image):
    command = next(at for cmd, at, _ in image["commands"] if cmd == 2)
    offset, count, strings, _ = struct.unpack_from("<4I", obj, command + 8)
    symbols = []
    for index in range(count):
        name, kind, _, _, address = struct.unpack_from("<IBBHQ", obj, offset + index * 16)
        name += strings
        symbols.append((obj[name:obj.index(b"\0", name)].decode(), kind, address))
    table = next(address for name, _, address in symbols if name == "__ZTV14Nx721jUsbBlock")
    section = next(s for segment in image["segments"] for s in segment["sections"]
                   if s["va"] <= table < s["va"] + s["size"])
    relocations, count = struct.unpack_from("<II", obj, section["command_offset"] + 56)
    slots = {}
    for index in range(count):
        address, flags = struct.unpack_from("<II", obj, relocations + index * 8)
        if flags >> 25 == 7:  # ARM64_RELOC_UNSIGNED, external, 8 byte payload
            slots[section["va"] + address - table] = symbols[flags & 0xffffff][0]
    methods = [slots.get(16 + i * 8) for i in range(ABI_SLOTS)]
    require(all(methods) and "___cxa_pure_virtual" not in methods
            and 16 + ABI_SLOTS * 8 not in slots, "Unexpected USB block virtual table shape")
    return methods, {name for name, kind, _ in symbols if kind == 1}


def sign_extend(value, bits):
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def pc_page(address, instruction):
    immediate = ((instruction >> 5 & 0x7ffff) << 2) | (instruction >> 29 & 3)
    return (address & ~4095) + sign_extend(immediate, 21) * 4096


def branch_target(address, instruction):
    return address + sign_extend(instruction & 0x3ffffff, 26) * 4


def storage_class_bindings(read, contains, text, exports, table, pointers):
    # Follow the original storage thunks to the named IOService base routines.
    def calls(address, name):
        require(contains("__TEXT_EXEC", address), "Storage thunk outside original text")
        page, load, branch = struct.unpack("<3I", read(address, 12))
        require(page & 0x9f00001f == 0x90000010 and load & 0xffc003ff == 0xf9400210
                and branch == 0xd61f0200, "Unexpected storage import thunk")
        slot = pc_page(address, page) + (load >> 10 & 4095) * 8
        target, = struct.unpack("<Q", read(slot, 8))
        return name in exports.get(target, ())

    code = read(text["va"], text["size"])
    constructors = []
    for offset in range(0, len(code) - 31, 4):
        words = struct.unpack_from("<8I", code, offset)
        if (words[:2] != (0xa9bf7bfd, 0x910003fd) or words[2] & 0xfc000000 != 0x94000000
                or words[3] & 0x9f00001f != 0x90000008 or words[4] & 0xffc003ff != 0x91000108
                or words[5:] != (0xf9000008, 0xa8c17bfd, 0xd65f03c0)):
            continue
        address = text["va"] + offset
        if pc_page(address + 12, words[3]) + (words[4] >> 10 & 4095) == table + 16:
            constructors.append((address, branch_target(address + 8, words[2])))
    require(len(constructors) == 1, "Cannot identify the protected storage constructor")
    constructor, thunk = constructors[0]
    require(calls(thunk, "__ZN9IOServiceC2EPK11OSMetaClass"), "Storage constructor target differs")

    require(all(contains("__TEXT_EXEC", address) and read(address, 4) == b"\x20\x00\x20\xd4"
                for address in pointers[:2]), "Unexpected abstract storage destructor entries")
    destructor = pointers[0] - 4
    require(contains("__TEXT_EXEC", destructor), "Storage base destructor outside original text")
    branch, = struct.unpack("<I", read(destructor, 4))
    require(branch & 0xfc000000 == 0x14000000
            and calls(branch_target(destructor, branch), "__ZN9IOServiceD2Ev"),
            "Storage base destructor target differs")

    getter = pointers[7]
    require(contains("__TEXT_EXEC", getter), "Storage metaclass getter outside original text")
    page, add, ret = struct.unpack("<3I", read(getter, 12))
    require(page & 0x9f00001f == 0x90000000 and add & 0xffc003ff == 0x91000000
            and ret == 0xd65f03c0, "Unexpected storage metaclass getter")
    metaclass = pc_page(getter, page) + (add >> 10 & 4095)
    require(contains("__DATA", metaclass), "Storage metaclass outside original data")
    return {
        "__ZN20IOBlockStorageDeviceC2EPK11OSMetaClass": constructor,
        "__ZN20IOBlockStorageDeviceD2Ev": destructor,
        "__ZN20IOBlockStorageDevice10gMetaClassE": metaclass,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("object", type=Path)
    parser.add_argument("kernel", type=Path)
    parser.add_argument("--native-prelink", type=Path, required=True)
    parser.add_argument("--linked", action="store_true", help="Verify the kernel's installed bindings")
    args = parser.parse_args()
    sys.path.insert(0, str(args.native_prelink))
    import native_prelink as np

    obj = args.object.read_bytes()
    kernel = args.kernel.read_bytes()
    plan = json.loads(args.kernel.with_suffix(".json").read_text())
    kernel_hash = hashlib.sha256(kernel).hexdigest()
    require(kernel_hash == plan["candidate_sha256"], "Kernel and prelink report differ")
    require(plan["original_sha256"] == "f18b4df865405f2a287b84977d7aca745e056d656d9fc9df1662970ce2969de7",
            "Unqualified NX721J storage input")
    image = np.macho(kernel)
    require(image["kind"] == 2, "Expected a prelinked executable")
    obj_image = np.macho(obj)
    require(obj_image["kind"] == 1, "Expected a USB driver object")
    exports = np.exports(kernel, image)
    by_name = {name: address for address, names in exports.items() for name in names}
    linked = {name: by_name.pop(name) for name in list(by_name) if "20IOBlockStorageDevice" in name}
    extents = {e["segment"]: e for e in plan["extents"] if e["module"] == BUNDLE}

    def read(address, size):
        offset = np.backed_offset(image["segments"], address, size, len(kernel))
        return kernel[offset:offset + size]

    def contains(segment, address):
        extent = extents[segment]
        return extent["va"] <= address < extent["va"] + extent["size"]

    text = extents["__TEXT_EXEC"]
    require(hashlib.sha256(read(text["va"], text["size"])).hexdigest()
            == plan["original_executable_sha256"][BUNDLE], "Storage text differs from the original")
    methods, imports = driver_table(obj, obj_image)
    inherited = {i: by_name[name] for i, name in enumerate(methods) if name in imports & by_name.keys()}
    require(len(inherited) >= 150, "Insufficient inherited kernel methods to identify the storage table")
    const = extents["__DATA_CONST"]
    blob = read(const["va"], const["size"])
    candidates = []
    for offset in range(0, len(blob) - (ABI_SLOTS + 2) * 8 + 1, 8):
        if blob[offset:offset + 16] != bytes(16):
            continue
        pointers = struct.unpack_from(f"<{ABI_SLOTS}Q", blob, offset + 16)
        if all(pointers[index] == address for index, address in inherited.items()):
            candidates.append((const["va"] + offset, pointers))
    require(len(candidates) == 1, f"Expected one NX721J storage virtual table, found {len(candidates)}")
    table, pointers = candidates[0]
    bindings = {"__ZTV20IOBlockStorageDevice": table}
    for name, pointer in zip(methods, pointers):
        if name not in imports or name in by_name:
            continue
        require("20IOBlockStorageDevice" in name and contains("__TEXT_EXEC", pointer),
                f"Unqualified virtual target for {name}")
        require(bindings.setdefault(name, pointer) == pointer, f"Ambiguous virtual target for {name}")
    bindings.update(storage_class_bindings(read, contains, text, exports, table, pointers))
    missing = imports - by_name.keys()
    require(missing == bindings.keys(),
            f"Unexpected storage binding set: {sorted(missing ^ bindings.keys())}")
    if args.linked:
        require(linked == bindings, "Linked storage symbols differ from original storage addresses")
        require("_nx721j_usb_publish_transport" in by_name, "USB driver is absent from the linked kernel")
    else:
        require(not linked, "Expected the original kernel before USB block linking")
    print(json.dumps({
        "kernel_sha256": kernel_hash,
        "object_sha256": hashlib.sha256(obj).hexdigest(),
        "virtual_slots": len(methods),
        "inherited_kernel_slots": len(inherited),
        "static_bindings": {name: hex(address) for name, address in sorted(bindings.items())},
        "linked_symbols_verified": args.linked,
        "runtime_qualified": False,
    }, indent=2))


if __name__ == "__main__":
    main()

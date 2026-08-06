#!/usr/bin/env python3
"""Report how much of its OTA slot the built app occupies, and fail when it is
close to full.

ESP-IDF already refuses to flash an app that does not fit, but that check fires
at 100% — by which point the build is broken and someone has to go find
kilobytes under pressure. This one fires early enough to be a warning.

The slot size is read from the partition table the build actually produced, not
from a constant. Enlarging the OTA partitions is a live option for this project,
and a hardcoded 1536K would quietly start reporting the wrong number the day
that happens.

Usage: check_app_size.py <build-dir> [--limit PERCENT] [--name LABEL]
Exit status is 1 when the app is at or over the limit.
"""

import argparse
import os
import struct
import sys

PARTITION_MAGIC = 0xAA50
PARTITION_ENTRY = "<HBBLL16sL"   # magic, type, subtype, offset, size, label, flags
ENTRY_SIZE = 32
TYPE_APP = 0x00
SUBTYPE_OTA_0 = 0x10


def ota_slot_size(table_path):
    """Size in bytes of the ota_0 partition, or None if it is not in the table."""
    with open(table_path, "rb") as f:
        blob = f.read()

    for offset in range(0, len(blob) - ENTRY_SIZE + 1, ENTRY_SIZE):
        magic, ptype, subtype, _, size, label, _ = struct.unpack_from(
            PARTITION_ENTRY, blob, offset)
        if magic != PARTITION_MAGIC:
            break   # end of table (or the MD5 entry, which has its own magic)
        if ptype == TYPE_APP and subtype == SUBTYPE_OTA_0:
            return size, label.rstrip(b"\x00").decode("utf-8", "replace")
    return None, None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--limit", type=int, default=95,
                    help="fail at or above this percentage (default: 95)")
    ap.add_argument("--name", default=None, help="label used in the output")
    ap.add_argument("--baseline", default=None,
                    help="previously published .bin to compare against")
    ap.add_argument("--summary", action="store_true",
                    help="append a row to $GITHUB_STEP_SUMMARY")
    args = ap.parse_args()

    name = args.name or os.path.basename(args.build_dir.rstrip("/"))
    app = os.path.join(args.build_dir, "esp32_nat_router.bin")
    table = os.path.join(args.build_dir, "partition_table", "partition-table.bin")

    for path in (app, table):
        if not os.path.isfile(path):
            sys.exit(f"{name}: missing {path}")

    slot, label = ota_slot_size(table)
    if slot is None:
        sys.exit(f"{name}: no ota_0 partition in {table}")

    size = os.path.getsize(app)
    free = slot - size
    percent = size * 100.0 / slot

    print(f"{name}: {size} / {slot} bytes in '{label}' "
          f"({percent:.1f}%, {free} free)")

    # Against the image currently published in firmware_<target>/, so a build
    # answers "how much did this actually save" and not just "does it fit".
    if args.baseline and os.path.isfile(args.baseline):
        was = os.path.getsize(args.baseline)
        delta = size - was
        print(f"{' ' * len(name)}  was {was} ({was * 100.0 / slot:.1f}%), "
              f"{'+' if delta > 0 else ''}{delta} bytes")

    if args.summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        state = "over" if percent >= args.limit else "ok"
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"| {name} | {size} | {percent:.1f}% | {free} | {state} |\n")

    if percent >= args.limit:
        print(f"::error::{name} fills {percent:.1f}% of its OTA slot "
              f"(limit {args.limit}%)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

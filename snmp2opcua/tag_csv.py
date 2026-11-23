"""Import/export device trap tags as a KEPServerEX-style tag CSV.

Uses the server's tag CSV columns, so a tag export from a KEPServerEX SNMP device can be
loaded directly:

    Tag Name, Address, Data Type, Respect Data Type, Client Access, Scan Rate, Scaling,
    Raw Low, Raw High, Scaled Low, Scaled High, Scaled Data Type, Clamp Low, Clamp High,
    Eng Units, Description, Negate Value

Only Tag Name and Address are required. Columns may be in any order. Comma or semicolon
delimiters are detected. Trap (TRAP_V1/TRAP_V2C), EVENTS_ and numeric OID addresses (polled
with SNMP GET; the device needs polling settings) are imported. Other addresses, such as
MIB names, are skipped and reported. Tag names may contain dots for tag
groups, e.g. "Traps.Port3Down".

    python -m snmp2opcua.tag_csv check tags.csv
    python -m snmp2opcua.tag_csv export -c config.yaml --device Channel1.Switch1 -o tags.csv
"""
from __future__ import annotations

import argparse
import csv
import re
import io
import sys
from pathlib import Path

from .snmp_driver import DeviceDef, DriverConfigError, TagDef, make_tag

COLUMNS = ["Tag Name", "Address", "Data Type", "Respect Data Type", "Client Access", "Scan Rate", "Scaling",
           "Raw Low", "Raw High", "Scaled Low", "Scaled High", "Scaled Data Type", "Clamp Low", "Clamp High",
           "Eng Units", "Description", "Negate Value"]
TRAP_PREFIXES = ("TRAP_V1:", "TRAP_V2C:", "EVENTS_")
_NUMERIC_OID = re.compile(r"^\.?[0-9]+(\.[0-9]+)+$")


class TagCsvError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems[:5]) + (f" (and {len(problems) - 5} more)" if len(problems) > 5 else ""))
        self.problems = problems


def _delimiter(text: str) -> str:
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    return ";" if first.count(";") > first.count(",") else ","


def read_tags(source: str | Path | io.TextIOBase, device: str = "") -> tuple[list[TagDef], list[str]]:
    """Parse a tag CSV. Returns (tags, skipped-row notes). Raises TagCsvError listing every bad row."""
    if isinstance(source, (str, Path)):
        text = Path(source).read_text(encoding="utf-8-sig")
    else:
        text = source.read()
    rows = list(csv.reader(io.StringIO(text), delimiter=_delimiter(text)))
    header_at = next((i for i, r in enumerate(rows) if any(c.strip().lower() == "tag name" for c in r)), None)
    if header_at is None:
        raise TagCsvError(["No header row with a 'Tag Name' column was found"])
    header = [c.strip().lower() for c in rows[header_at]]
    if "address" not in header:
        raise TagCsvError(["The header row has no 'Address' column"])
    col = {name: header.index(name) for name in header if name}

    def cell(row, name):
        i = col.get(name)
        return row[i].strip() if i is not None and i < len(row) else ""

    tags: list[TagDef] = []
    skipped: list[str] = []
    problems: list[str] = []
    names: set[str] = set()
    for n, row in enumerate(rows[header_at + 1:], start=header_at + 2):
        if not any(c.strip() for c in row):
            continue
        name, address = cell(row, "tag name"), cell(row, "address")
        if not name or not address:
            problems.append(f"Row {n}: Tag Name and Address are required")
            continue
        if not (address.upper().startswith(TRAP_PREFIXES) or _NUMERIC_OID.match(address)):
            skipped.append(f"Row {n}: {name} ({address}) is not a trap, EVENTS_ or numeric OID address, skipped")
            continue
        if name in names:
            problems.append(f"Row {n}: the tag {name} has already been added")
            continue
        try:
            tags.append(make_tag(name, address, cell(row, "data type") or None, cell(row, "description"), device))
            names.add(name)
        except DriverConfigError as exc:
            problems.append(f"Row {n}: {exc}")
    if problems:
        raise TagCsvError(problems)
    return tags, skipped


def write_tags(tags: list[TagDef], dest: str | Path | io.TextIOBase, delimiter: str = ",",
               include_auto: bool = False) -> int:
    """Write tags in the server's CSV layout. Auto-created tags are left out unless asked for."""
    rows = [t for t in tags if include_auto or not t.auto]
    out = io.StringIO()
    w = csv.writer(out, delimiter=delimiter, lineterminator="\r\n")
    w.writerow(COLUMNS)
    for t in rows:
        access = "R/W" if t.writable else "RO"
        w.writerow([t.name, t.address.text(), t.data_type, 1, access, 100, "", "", "", "", "", "", "", "", "",
                    t.description, ""])
    if isinstance(dest, (str, Path)):
        Path(dest).write_text(out.getvalue(), encoding="utf-8")
    else:
        dest.write(out.getvalue())
    return len(rows)


def csv_loader(path: str, base_dir, device: str) -> list[TagDef]:
    """Used by the config loader for a device's `tags_csv:` (path relative to the config file)."""
    p = Path(path)
    if not p.is_absolute() and base_dir is not None:
        p = Path(base_dir) / p
    try:
        tags, _ = read_tags(p, device)
    except FileNotFoundError:
        raise DriverConfigError(f"Device {device}: tags_csv file {p} does not exist") from None
    except TagCsvError as exc:
        raise DriverConfigError(f"Device {device}: {p.name}: {exc}") from None
    return tags


def find_device(devices: list[DeviceDef], path: str) -> DeviceDef:
    for d in devices:
        if d.path == path:
            return d
    raise SystemExit(f"No device {path!r}. Devices: {', '.join(d.path for d in devices) or 'none'}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="snmp2opcua.tag_csv", description="Import/export trap tags as tag CSV")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="validate a tag CSV file")
    c.add_argument("file")
    e = sub.add_parser("export", help="export a device's tags from the configuration")
    e.add_argument("-c", "--config", default="config.yaml")
    e.add_argument("--device", required=True, help="Channel.Device")
    e.add_argument("-o", "--output", required=True)
    e.add_argument("--semicolon", action="store_true", help="use ; as the delimiter")
    e.add_argument("--all", action="store_true", help="include auto-created and EVENTS_ tags")
    args = ap.parse_args(argv)
    if args.cmd == "check":
        try:
            tags, skipped = read_tags(args.file)
        except TagCsvError as exc:
            print("\n".join(exc.problems), file=sys.stderr)
            return 1
        for note in skipped:
            print(note)
        print(f"OK: {len(tags)} trap tags")
        return 0
    from .config import load_config
    cfg = load_config(args.config)
    dev = find_device(cfg["_devices"], args.device)
    n = write_tags(dev.tags, args.output, ";" if args.semicolon else ",", include_auto=args.all)
    print(f"Exported {n} tags from {dev.path} to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Assemble the integrated experimental 65:24 write list and container.

Sources: the core candidate (ratio stub, size rows, RAW crop lookup) minus its
placeholder preview rows, plus the preview alias experiment that replaces
them. Output is an offline experimental container plus manifest; it is not a
camera-accepted update.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.x100v_update_package import STOCK_SHA256, audit_container, build_container

CORE_MANIFEST = Path("build/x100v-xpan-core-experimental-20261027-b/manifest.json")
ALIAS_MANIFEST = Path("build/x100v-preview-alias-experimental-20261028-a/manifest.json")
# Revision b: makes aspect 4 available for the IMAGE SIZE menu (card 3b showed
# no 65:24 option with the 19 writes alone).
MENU_MANIFEST = Path("build/x100v-aspect-menu-availability-20261102-a/manifest.json")
# Revision c: adds 65:24 sizes to the size rule table (card 3d ran from the card
# and still showed no 65:24 option).
SIZE_RULE_MANIFEST = Path("build/x100v-size-rule-table-20261102-a/manifest.json")
# Revision d: swaps the 16:9 sizes in the IMAGE SIZE menu value lists for the
# 65:24 sizes (card 3e still showed no 65:24 option).
MENU_LISTS_MANIFEST = Path("build/x100v-menu-value-lists-20261102-a/manifest.json")
EXPECTED_ALIAS_FIELDS = ["lookup-entry", "dimension-entry", "preview-alias-stubs"]


def integrated_writes(menu_availability: bool = False, size_rule_table: bool = False,
                      menu_value_lists: bool = False) -> list[dict]:
    core = json.loads(CORE_MANIFEST.read_text())
    alias = json.loads(ALIAS_MANIFEST.read_text())
    menu = json.loads(MENU_MANIFEST.read_text()) if menu_availability else {"writes": []}
    rule = json.loads(SIZE_RULE_MANIFEST.read_text()) if size_rule_table else {"writes": []}
    lists = json.loads(MENU_LISTS_MANIFEST.read_text()) if menu_value_lists else {"writes": []}
    extra = [m for m, used in ((menu, menu_availability), (rule, size_rule_table),
                               (lists, menu_value_lists)) if used]
    for manifest in (core, alias, *extra):
        if manifest["source_update_sha256"] != STOCK_SHA256:
            raise ValueError("candidate manifest is bound to a different update")
    kept = [w for w in core["writes"] if not w["field"].startswith("preview-code4-row-")]
    if len(kept) != 16 or len(core["writes"]) - len(kept) != 6:
        raise ValueError("core manifest no longer has 16 kept and 6 placeholder writes")
    if [w["field"] for w in alias["writes"]] != EXPECTED_ALIAS_FIELDS:
        raise ValueError("alias manifest write fields differ")
    keys = ("field", "partition_offset", "before_hex", "after_hex")
    return [{k: w[k] for k in keys} for w in [*kept, *alias["writes"], *menu["writes"], *rule["writes"],
                                                 *lists["writes"]]]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--stock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--write-container", action="store_true")
    parser.add_argument("--menu-availability", action="store_true",
                        help="include revision b's aspect-4 availability write")
    parser.add_argument("--size-rule-table", action="store_true",
                        help="include revision c's size rule table writes")
    parser.add_argument("--menu-value-lists", action="store_true",
                        help="include revision d's menu value list swap")
    args = parser.parse_args()
    raw = args.stock.read_bytes()
    writes = integrated_writes(args.menu_availability, args.size_rule_table, args.menu_value_lists)
    candidate, stats = build_container(raw, writes)
    audit = audit_container(raw, candidate, writes)
    manifest = {
        "kind": "integrated experimental 65:24 update container; offline only",
        "flashable": False,
        "camera_updater_acceptance_verified": False,
        "rollback_verified": False,
        "finder_and_saved_file_verified": False,
        "source_update_sha256": STOCK_SHA256,
        "sources": [str(CORE_MANIFEST), str(ALIAS_MANIFEST),
                    *([str(MENU_MANIFEST)] if args.menu_availability else []),
                    *([str(SIZE_RULE_MANIFEST)] if args.size_rule_table else []),
                    *([str(MENU_LISTS_MANIFEST)] if args.menu_value_lists else [])],
        "excluded": "core preview-code4-row placeholder writes (superseded by alias)",
        "write_count": len(writes),
        "writes": writes,
        "build": stats,
        "audit": audit,
        "remaining_gates": [
            "cache freshness for aliased preview rows",
            "stub page executable at runtime",
            "camera updater acceptance of a modified container",
            "rollback path proven before any flash",
            "same-scene LCD/EVF/OVF and independent JPEG/RAF inspection",
        ],
    }
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (args.output_dir / "writes.json").write_text(json.dumps(writes, indent=2) + "\n")
    if args.write_container:
        (args.output_dir / "candidate-update-NOT-FOR-CARD.DAT").write_bytes(candidate)
    print(json.dumps({k: manifest[k] for k in ("write_count", "build", "audit")}, indent=2))
    print("container sha256", hashlib.sha256(candidate).hexdigest())


if __name__ == "__main__":
    main()

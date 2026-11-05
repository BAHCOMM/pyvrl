"""Builds the OCSF catalogue shipped with pyvrl.

Compile the schema first, using the official compiler at a pinned tag:

    git clone --depth 1 --branch 1.9.0 https://github.com/ocsf/ocsf-schema.git
    pip install ocsf-schema-compiler
    ocsf-schema-compiler -i ocsf-schema > compiled.json

then run:

    python scripts/build_ocsf_data.py compiled.json
"""

import gzip
import json
import re
import sys
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "python" / "pyvrl" / "ocsf" / "data"
MAX_DESCRIPTION = 240


def short_description(text):
    """First sentence of a description, without HTML, for editor tooltips."""
    plain = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", text or "")).strip()
    sentence = re.split(r"(?<=[.!?])\s", plain, maxsplit=1)[0]
    return sentence[:MAX_DESCRIPTION]


def slim_attribute(attribute):
    slim = {"type": attribute["type"], "caption": attribute.get("caption", "")}
    slim["description"] = short_description(attribute.get("description"))
    for key in ("object_type", "requirement", "profiles"):
        if attribute.get(key):
            slim[key] = attribute[key]
    if attribute.get("is_array"):
        slim["is_array"] = True
    if "@deprecated" in attribute:
        slim["deprecated"] = True
    if "enum" in attribute:
        slim["enum"] = {key: item.get("caption", "") for key, item in attribute["enum"].items()}
    return slim


def slim_entity(entity):
    slim = {
        "caption": entity.get("caption", ""),
        "description": short_description(entity.get("description")),
        "attributes": {
            name: slim_attribute(attribute)
            for name, attribute in entity.get("attributes", {}).items()
        },
    }
    if entity.get("constraints"):
        slim["constraints"] = entity["constraints"]
    if "@deprecated" in entity:
        slim["deprecated"] = True
    for key in ("uid", "category_uid", "category_name"):
        if key in entity:
            slim[key] = entity[key]
    return slim


def base_types(compiled):
    """Maps each OCSF type to the primitive it is built on, such as ip_t to string_t."""
    types = compiled["dictionary"]["types"]["attributes"]
    return {name: item.get("type", name) for name, item in types.items()}


def main(compiled_path):
    compiled = json.loads(Path(compiled_path).read_text())
    version = compiled["version"]
    catalogue = {
        "version": version,
        "types": base_types(compiled),
        "profiles": sorted(compiled["profiles"]),
        "classes": {name: slim_entity(item) for name, item in compiled["classes"].items()},
        "objects": {name: slim_entity(item) for name, item in compiled["objects"].items()},
    }
    payload = json.dumps(catalogue, separators=(",", ":"), sort_keys=True).encode()
    output = DATA_DIR / f"ocsf-{version}.json.gz"
    output.write_bytes(gzip.compress(payload, mtime=0))
    print(f"{output}: {len(catalogue['classes'])} classes, "
          f"{len(catalogue['objects'])} objects, {output.stat().st_size // 1024} KB")


if __name__ == "__main__":
    main(sys.argv[1])

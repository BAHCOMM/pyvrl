"""Generates the JSON Schema that gives editors autocomplete for mapping files.

Nested fields use `$ref`, so completion works to any depth without listing every
path. Any field also accepts a string, which is a VRL expression.
"""

import json

from .schema import OCSF_VERSION, base_type, catalogue

GENERATED_FIELDS = {"class_uid", "class_name", "category_uid", "category_name", "type_uid"}
VRL_EXPRESSION = {"type": "string", "description": "A VRL expression."}
JSON_TYPES = {
    "boolean_t": "boolean",
    "float_t": "number",
    "integer_t": "integer",
    "long_t": "integer",
}


def mapping_schema():
    """Returns the JSON Schema for mapping files as a dict."""
    data = catalogue()
    definitions = {}
    for name, entity in data["classes"].items():
        definitions[f"class_{name}"] = _entity_schema(entity, GENERATED_FIELDS)
    for name, entity in data["objects"].items():
        definitions[f"object_{name}"] = _entity_schema(entity, {"version"} if name == "metadata"
                                                       else set())
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": f"pyvrl OCSF {OCSF_VERSION} mapping",
        "type": "object",
        "additionalProperties": False,
        "required": ["source", "routes"],
        "properties": {
            "source": {"type": "string", "description": "Name of the log source."},
            "let": {
                "type": "object",
                "description": "Variables computed before routing, as VRL expressions.",
                "additionalProperties": {"type": "string"},
            },
            "routes": {"type": "array", "minItems": 1, "items": _route_schema(data)},
        },
        "$defs": definitions,
    }


def _route_schema(data):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["class", "fields"],
        "properties": {
            "when": {"type": "string", "description": "VRL condition. Omit on the last route."},
            "class": {"enum": sorted(n for n, c in data["classes"].items()
                                     if not c.get("deprecated"))},
            "profiles": {"type": "array", "items": {"enum": data["profiles"]}},
            "fields": {"type": "object"},
        },
        "allOf": [
            {
                "if": {"properties": {"class": {"const": name}}, "required": ["class"]},
                "then": {"properties": {"fields": {"$ref": f"#/$defs/class_{name}"}}},
            }
            for name in data["classes"]
        ],
    }


def _entity_schema(entity, hidden):
    attributes = {name: item for name, item in entity["attributes"].items() if name not in hidden}
    required = [name for name, item in attributes.items()
                if item.get("requirement") == "required" and not item.get("profiles")]
    schema = {
        "type": "object",
        "description": entity.get("description", ""),
        "additionalProperties": False,
        "properties": {name: _attribute_schema(item) for name, item in attributes.items()},
    }
    if required:
        schema["required"] = sorted(required)
    return schema


def _attribute_schema(attribute):
    single = _value_schema(attribute)
    if attribute.get("is_array"):
        single = {"type": "array", "items": single}
    return {
        "description": _describe(attribute),
        "anyOf": [single, VRL_EXPRESSION],
    }


def _value_schema(attribute):
    if "enum" in attribute:
        return {"enum": sorted(int(key) for key in attribute["enum"] if key.lstrip("-").isdigit())}
    if attribute["type"] == "object_t":
        name = attribute.get("object_type")
        return {"$ref": f"#/$defs/object_{name}"} if name in catalogue()["objects"] else {}
    primitive = JSON_TYPES.get(base_type(attribute["type"]))
    return {"type": primitive} if primitive else {}


def _describe(attribute):
    parts = [f"{attribute['caption']}: {attribute['description']}".strip()]
    if attribute.get("requirement"):
        parts.append(f"({attribute['requirement']})")
    if attribute.get("profiles"):
        parts.append(f"Needs profile: {', '.join(attribute['profiles'])}.")
    if "enum" in attribute:
        parts.append(", ".join(f"{key} = {name}" for key, name in attribute["enum"].items()))
    return " ".join(parts)


def write_mapping_schema(path):
    with open(path, "w", encoding="utf-8") as output:
        json.dump(mapping_schema(), output, indent=1, sort_keys=True)
        output.write("\n")

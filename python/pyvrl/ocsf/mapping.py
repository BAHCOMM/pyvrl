"""Compiles YAML mappings into VRL programs that produce OCSF events.

A mapping lists routes, and the first route whose `when` matches converts the
event. Strings under `fields` are VRL expressions, so a literal needs quotes
inside the YAML string: `'"AWS"'`. Numbers and booleans are literals.
"""

import json
import logging
import warnings
from pathlib import Path

import yaml

from .. import Transform
from .schema import OCSF_VERSION, catalogue
from .validate import validate

logger = logging.getLogger("pyvrl.ocsf")

OUTPUT = "ocsf_out"
ON_INVALID = ("warn", "raise", "ignore")
BUILTIN_DIR = Path(__file__).parent / "mappings"


class MappingError(ValueError):
    """A mapping file does not match OCSF, or is not valid."""


class NoRouteError(ValueError):
    """No route in the mapping matched the event."""


class InvalidEventError(ValueError):
    """A converted event is not valid OCSF. Only raised with on_invalid="raise"."""


class Mapping:
    """Converts one log source to OCSF."""

    def __init__(self, document, *, on_invalid="warn"):
        if on_invalid not in ON_INVALID:
            raise ValueError(f"on_invalid must be one of {', '.join(ON_INVALID)}")
        self.on_invalid = on_invalid
        self.source = document.get("source", "<unnamed>")
        self.vrl = compile_mapping(document)
        self._transform = Transform(self.vrl)

    @classmethod
    def load(cls, path, **options):
        return cls(yaml.safe_load(Path(path).read_text()), **options)

    @classmethod
    def builtin(cls, source, **options):
        """Loads a mapping shipped with pyvrl, such as "aws_cloudtrail"."""
        path = BUILTIN_DIR / f"{source}.yaml"
        if not path.is_file():
            raise MappingError(f"no built-in mapping for {source!r}")
        return cls.load(path, **options)

    def convert(self, event):
        """Converts one event to OCSF.

        Raises NoRouteError if no route matches, and ValueError if the mapping
        fails on this event, such as a timestamp that cannot be parsed.
        """
        output = self._transform.remap(event)
        if output is None:
            raise NoRouteError(f"{self.source}: no route matched the event")
        if self.on_invalid != "ignore":
            self._report(validate(output))
        return output

    def _report(self, problems):
        if not problems:
            return
        message = f"{self.source}: invalid OCSF: {'; '.join(problems)}"
        if self.on_invalid == "raise":
            raise InvalidEventError(message)
        logger.warning(message)


def compile_mapping(document):
    """Turns a parsed mapping into a VRL program, checking it against OCSF."""
    routes = document.get("routes")
    if not routes:
        raise MappingError("a mapping needs at least one route")

    lines = [f"{OUTPUT} = {{}}"]
    for name, expression in (document.get("let") or {}).items():
        lines.append(f"{name} = {expression}")

    branches = []
    for index, route in enumerate(routes):
        branches.append((route.get("when"), _compile_route(route)))
        if "when" not in route and index != len(routes) - 1:
            raise MappingError(f"route {index} has no `when`, so later routes can't match")
    lines += _branch_lines(branches)
    lines.append(f"compact({OUTPUT})")
    return "\n".join(lines) + "\n"


def _branch_lines(branches):
    lines = []
    keyword = "if"
    for condition, body in branches:
        if condition is None:
            if lines:
                lines.append("} else {")
                lines += body
            else:
                return body
            lines.append("}")
            return lines
        lines.append(f"{keyword} {condition} {{" if keyword == "if"
                     else f"}} else if {condition} {{")
        lines += body
        keyword = "else if"
    lines += ["} else {", "  return null", "}"]
    return lines


def _compile_route(route):
    name = route.get("class")
    entity = catalogue()["classes"].get(name)
    if entity is None:
        raise MappingError(f"unknown OCSF class {name!r}")
    if entity.get("deprecated"):
        warnings.warn(f"OCSF class {name!r} is deprecated", DeprecationWarning, stacklevel=2)

    profiles = route.get("profiles") or []
    unknown = sorted(set(profiles) - set(catalogue()["profiles"]))
    if unknown:
        raise MappingError(f"unknown OCSF profile {unknown[0]!r}")

    lines = []
    _emit_entity(_with_generated_fields(route, entity, profiles), entity, set(profiles),
                 OUTPUT, name, lines)
    return lines


def _with_generated_fields(route, entity, profiles):
    """Adds the fields that follow from the class, so mappings don't repeat them."""
    fields = dict(route.get("fields") or {})
    metadata = dict(fields.get("metadata") or {})
    metadata["version"] = json.dumps(OCSF_VERSION)
    if profiles:
        metadata["profiles"] = json.dumps(sorted(profiles))
    fields["metadata"] = metadata
    fields["class_uid"] = entity["uid"]
    fields["class_name"] = json.dumps(entity["caption"])
    fields["category_uid"] = entity["category_uid"]
    fields["category_name"] = json.dumps(entity["category_name"])
    # `get` hides the field's type from VRL, which otherwise rejects `??` when
    # activity_id is a literal, because that can't fail.
    activity = f'(get({OUTPUT}, ["activity_id"]) ?? 0)'
    fields["type_uid"] = f"{entity['uid']} * 100 + (int{activity} ?? 0)"
    return fields


def _emit_entity(fields, entity, profiles, target, where, lines):
    attributes = entity["attributes"]
    for field, attribute in attributes.items():
        if attribute.get("requirement") != "required" or field in fields:
            continue
        declared_by = attribute.get("profiles")
        if not declared_by or profiles.intersection(declared_by):
            raise MappingError(f"{where}: missing required field {field}")
    for field, value in fields.items():
        attribute = attributes.get(field)
        if attribute is None:
            raise MappingError(f"{where}: unknown field {field}")
        declared_by = attribute.get("profiles")
        if declared_by and not profiles.intersection(declared_by):
            raise MappingError(f"{where}: {field} needs one of the profiles "
                               f"{', '.join(declared_by)}")
        if attribute.get("deprecated"):
            warnings.warn(f"{where}.{field} is deprecated", DeprecationWarning, stacklevel=2)
        _emit_value(value, attribute, profiles, f"{target}.{field}", f"{where}.{field}", lines)


def _emit_value(value, attribute, profiles, target, where, lines):
    if isinstance(value, dict):
        entity = catalogue()["objects"].get(attribute.get("object_type"))
        if entity is None:
            raise MappingError(f"{where}: is not an object")
        lines.append(f"{target} = {{}}")
        _emit_entity(value, entity, profiles, target, where, lines)
    elif isinstance(value, list):
        if not attribute.get("is_array"):
            raise MappingError(f"{where}: is not an array")
        lines.append(f"{target} = []")
        single = {key: item for key, item in attribute.items() if key != "is_array"}
        for index, item in enumerate(value):
            _emit_value(item, single, profiles, f"{target}[{index}]", f"{where}[{index}]", lines)
    elif isinstance(value, str):
        lines.append(f"{target} = {value}")
    else:
        if "enum" in attribute and str(value) not in attribute["enum"]:
            raise MappingError(f"{where}: invalid value {value!r}")
        lines.append(f"{target} = {json.dumps(value)}")

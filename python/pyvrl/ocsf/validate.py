"""Checks events against the OCSF catalogue."""

import ipaddress

from .schema import base_type, catalogue, classes_by_uid

PRIMITIVES = {
    "string_t": str,
    "integer_t": int,
    "long_t": int,
    "float_t": (int, float),
    "boolean_t": bool,
}


def validate(event):
    """Returns a list of problems with an OCSF event, empty if it is valid."""
    if not isinstance(event, dict):
        return [f"event is {type(event).__name__}, not an object"]
    name = classes_by_uid().get(event.get("class_uid"))
    if name is None:
        return [f"unknown class_uid {event.get('class_uid')!r}"]
    metadata = event.get("metadata")
    profiles = metadata.get("profiles") if isinstance(metadata, dict) else None
    entity = catalogue()["classes"][name]
    return _check_entity(event, entity, set(profiles or ()), "")


def _check_entity(value, entity, profiles, path):
    problems = []
    attributes = entity["attributes"]
    for field, attribute in attributes.items():
        required = attribute.get("requirement") == "required"
        if required and field not in value and _is_active(attribute, profiles):
            problems.append(f"missing required {path}{field}")
    for field, item in value.items():
        attribute = attributes.get(field)
        if attribute is None:
            problems.append(f"unknown field {path}{field}")
        else:
            problems += _check_attribute(item, attribute, profiles, f"{path}{field}")
    problems += _check_constraints(value, entity, path)
    return problems


def _is_active(attribute, profiles):
    """Fields from an OCSF profile only apply to events that declare the profile."""
    declared_by = attribute.get("profiles")
    return not declared_by or bool(profiles.intersection(declared_by))


def _check_constraints(value, entity, path):
    constraints = entity.get("constraints") or {}
    where = path.rstrip(".") or "event"
    problems = []
    fields = constraints.get("at_least_one")
    if fields and not any(field in value for field in fields):
        problems.append(f"{where} needs at least one of {', '.join(fields)}")
    fields = constraints.get("just_one")
    if fields and sum(field in value for field in fields) != 1:
        problems.append(f"{where} needs exactly one of {', '.join(fields)}")
    return problems


def _check_attribute(value, attribute, profiles, path):
    if attribute.get("is_array"):
        if not isinstance(value, list):
            return [f"{path} must be an array"]
        problems = []
        for index, item in enumerate(value):
            problems += _check_value(item, attribute, profiles, f"{path}[{index}]")
        return problems
    return _check_value(value, attribute, profiles, path)


def _check_value(value, attribute, profiles, path):
    if "enum" in attribute and str(value) not in attribute["enum"]:
        return [f"{path} has invalid value {value!r}"]
    if attribute["type"] == "object_t":
        return _check_object(value, attribute, profiles, path)
    return _check_primitive(value, attribute["type"], path)


def _check_object(value, attribute, profiles, path):
    if not isinstance(value, dict):
        return [f"{path} must be an object"]
    entity = catalogue()["objects"].get(attribute.get("object_type"))
    # OCSF's generic `object` type has no fields, so it accepts anything.
    if entity is None or not entity["attributes"]:
        return []
    return _check_entity(value, entity, profiles, f"{path}.")


def _check_primitive(value, type_name, path):
    expected = PRIMITIVES.get(base_type(type_name))
    if expected is None:
        return []
    # bool is a subclass of int in Python, but not in OCSF.
    is_bool_mismatch = isinstance(value, bool) and expected is not bool
    if is_bool_mismatch or not isinstance(value, expected):
        return [f"{path} must be {base_type(type_name).removesuffix('_t')}, "
                f"not {type(value).__name__}"]
    if type_name == "ip_t" and not _is_ip(value):
        return [f"{path} is not an IP address: {value!r}"]
    return []


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True

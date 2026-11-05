import datetime, uuid
import pytest
from pyvrl import Transform

def run(src, data=None):
    return Transform(src).remap({} if data is None else data)

def test_readme_example():
    out = run('.y = "bar"\n.x = upcase!(.x)\n.z = uuid_v7()\n.', {"x": "foo"})
    assert out["x"] == "FOO" and out["y"] == "bar"
    uuid.UUID(out["z"])

def test_string_literal_is_not_none():
    assert run('"hello"') == "hello"

def test_scalar_outputs():
    assert run('.a = 1\n.b = 1.5\n.c = true\n.d = null\n.') == {"a": 1, "b": 1.5, "c": True, "d": None}

def test_nested_output():
    assert run('.a = {"b": ["c", 1, {"d": "e"}]}\n.') == {"a": {"b": ["c", 1, {"d": "e"}]}}

def test_timestamp_output():
    out = run('.t = t\'2024-01-02T03:04:05Z\'\n.')["t"]
    assert out == datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)

def test_regex_output_stays_none():
    assert run('r\'abc\'') is None

@pytest.mark.parametrize("value", [True, False, 7, -7, 1.25, None, "str", "üñí", ["a", 1, None], {"k": {"n": [1, "x"]}}])
def test_roundtrip(value):
    assert run('.v', {"v": value}) == value
    assert type(run('.v', {"v": value})) is type(value)

def test_bytes_input_becomes_str():
    assert run('.v', {"v": b"abc"}) == "abc"

def test_non_utf8_bytes_are_lossy():
    assert run('.v', {"v": b"a\xffb"}) == "a�b"

def test_str_input_works_with_string_functions():
    out = run('.a = upcase!(.s)\n.b = .s == "abc"\n.c = length!(.s)\n.d = contains!(.s, "b")\n.e = parse_json!(.j)\n.',
              {"s": "abc", "j": '{"k": "v"}'})
    assert (out["a"], out["b"], out["c"], out["d"], out["e"]) == ("ABC", True, 3, True, {"k": "v"})

def test_str_and_bytes_compare_equal():
    assert run('.a == .b', {"a": "x", "b": b"x"}) is True

def test_compile_error():
    with pytest.raises(ValueError):
        Transform('.a = nope(')

def test_runtime_error():
    with pytest.raises(ValueError, match="remap failure"):
        run('upcase!(.x)', {"x": 1})

def test_nan_rejected():
    with pytest.raises(ValueError, match="NaN"):
        run('.', {"x": float("nan")})

@pytest.mark.parametrize("bad", [{"x": object()}, {"x": (1, 2)}, {"x": {1, 2}}])
def test_unsupported_types(bad):
    with pytest.raises(TypeError, match="Unsupported type"):
        run('.', bad)

def test_non_string_key_rejected():
    with pytest.raises(TypeError):
        run('.', {1: "x"})

def test_int_overflow_rejected():
    with pytest.raises(OverflowError):
        run('.', {"x": 2**70})

def test_source_attr_and_reuse():
    t = Transform('.y = "z"\n.')
    assert t.source == '.y = "z"\n.'
    assert t.remap({}) == t.remap({}) == {"y": "z"}


def nested(levels):
    """A value made of `levels` nested lists."""
    value = None
    for _ in range(levels):
        value = [value]
    return value


def test_return_stops_and_emits_value():
    assert run('.a = 1\nreturn {"b": 2}\n.c = 3\n.') == {"b": 2}

def test_return_in_conditional():
    source = 'if .x == 1 { return "early" }\n"late"'
    assert run(source, {"x": 1}) == "early"
    assert run(source, {"x": 2}) == "late"

def test_abort_still_raises():
    with pytest.raises(ValueError, match="remap failure"):
        run('abort "nope"')

def test_max_depth_accepted():
    assert run('.', nested(128)) == nested(128)

def test_past_max_depth_rejected():
    with pytest.raises(RecursionError):
        run('.', nested(129))

def test_very_deep_input_rejected():
    with pytest.raises(RecursionError):
        run('.', nested(100_000))

def test_cyclic_list_rejected():
    value = []
    value.append(value)
    with pytest.raises(RecursionError):
        run('.', {"a": value})

def test_cyclic_dict_rejected():
    value = {}
    value["self"] = value
    with pytest.raises(RecursionError):
        run('.', value)

def test_program_cannot_nest_output_past_limit():
    with pytest.raises(RecursionError):
        run('. = [[.]]\n.', nested(128))

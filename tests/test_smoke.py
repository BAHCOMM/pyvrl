import datetime, random, threading, uuid
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

def test_program_cannot_nest_dict_output_past_limit():
    value = None
    for _ in range(128):
        value = {"k": value}
    with pytest.raises(RecursionError):
        run('. = {"w": {"w": .}}\n.', value)

def test_invalid_unicode_str_rejected():
    with pytest.raises(UnicodeEncodeError):
        run('.', {"a": "\ud800"})

@pytest.mark.parametrize("name", ["bool", "bytes", "dict", "float", "int", "list", "str"])
def test_lookalike_class_name_rejected(name):
    with pytest.raises(TypeError):
        run('.', {"a": type(name, (), {})()})

@pytest.mark.parametrize("source", ['.a = ', '.a = "unterminated', 'if {', '{{{', ')', 'nope()', '\x00', '.a = 1 +'])
def test_malformed_program_raises_value_error(source):
    with pytest.raises(ValueError):
        Transform(source)

@pytest.mark.parametrize("function", ["parse_json", "parse_syslog", "parse_common_log", "parse_key_value", "parse_url", "parse_xml", "parse_int", "decode_base64"])
@pytest.mark.parametrize("garbage", ["", "\x00", "{", "<a", "[" * 5000, '{"a":' * 5000, "�" * 100])
def test_parse_functions_survive_garbage(function, garbage):
    result = run(f'x, err = {function}(.s)\n{{"ok": err == null}}', {"s": garbage})
    assert isinstance(result["ok"], bool)

def test_mutated_programs_never_crash():
    """Malformed programs must fail with ValueError, never a panic or segfault."""
    rng = random.Random(0)
    seeds = [
        '.y = "bar"\n.x = upcase!(.x)\n.',
        'if .a == 1 { .b = [1, {"c": 2}] } else { abort "no" }\n.',
        '. = map_values(.) -> |v| { v }\n.',
        '.j = parse_json!(.s) ?? {}\n.',
        'del(.a)\nreturn .\n',
    ]
    tokens = ['{', '}', '[', ']', '(', ')', '!', '??', '|', '"', "'", '\\', '.', '=', '\n', '#', "r'", "t'", 'abort', '\x00', '😀']
    for _ in range(3000):
        source = rng.choice(seeds)
        for _ in range(rng.randint(1, 6)):
            i = rng.randint(0, len(source))
            source = source[:i] + rng.choice([rng.choice(tokens), '']) + source[i + rng.randint(0, 8):]
        try:
            program = Transform(source)
        except ValueError:
            continue
        try:
            program.remap({"a": 1, "x": "y", "s": source})
        except (ValueError, TypeError):
            pass


DEEP_PROGRAMS = {
    "arrays": lambda n: "[" * n + "]" * n,
    "objects": lambda n: '{"a":' * n + "1" + "}" * n,
    "groups": lambda n: "(" * n + "1" + ")" * n,
    "additions": lambda n: "+".join(["1"] * n),
    "multiline_additions": lambda n: "1" + " +\n1" * n,
    "negations": lambda n: "!" * n + "true",
    "ifs": lambda n: "if .a == 1 { " * n + "1" + " }" * n,
    "else_ifs": lambda n: "if .a == 0 { 0 }" + " else if .a == 0 { 0 }" * n + " else { 1 }",
    "coalesces": lambda n: " ?? ".join(["to_int(.a)"] * n) + " ?? 0",
    "calls": lambda n: "upcase!(" * n + ".s" + ")" * n,
    "closures": lambda n: "map_values(.) -> |v| { " * n + "v" + " }" * n,
    "assigned_path": lambda n: ".a" * n + " = 1\ntrue",
    "read_path": lambda n: ".a" * n,
    "assigned_index": lambda n: ".a" + "[0]" * n + " = 1\ntrue",
}

@pytest.mark.parametrize("shape", DEEP_PROGRAMS)
def test_deep_program_rejected_not_crashed(shape):
    with pytest.raises(ValueError, match="levels deep, the limit is 128"):
        Transform(DEEP_PROGRAMS[shape](5000))

def test_broken_deep_program_is_a_syntax_error_not_a_crash():
    with pytest.raises(ValueError, match="syntax error"):
        Transform("1" + "+1" * 100_000 + " )")

def test_path_at_limit_accepted():
    Transform(".a" * 128 + " = 1\ntrue")

def test_path_past_limit_rejected():
    with pytest.raises(ValueError, match="129 levels deep"):
        Transform(".a" * 129 + " = 1\ntrue")

def test_long_flat_program_accepted():
    assert run('.a = 1\n' * 10_000 + '.') == {"a": 1}

def test_nested_program_at_limit_runs_on_worker_thread():
    program = Transform("x = to_int!(.a)\n" + " + ".join(["x"] * 120))
    results = []
    previous = threading.stack_size(1024 * 1024)
    try:
        worker = threading.Thread(target=lambda: results.append(program.remap({"a": 1})))
        worker.start()
        worker.join()
    finally:
        threading.stack_size(previous)
    assert results == [120]

DEEP_ARRAY = "[" * 200 + "]" * 200

@pytest.mark.parametrize("source", [
    f"if (true; {DEEP_ARRAY}) {{ 1 }}",
    f"_ = {DEEP_ARRAY}",
    f"_, err = parse_json({DEEP_ARRAY})",
    f"upcase!({DEEP_ARRAY}).a",
    f"{DEEP_ARRAY}[0]",
    f'{{"a": {DEEP_ARRAY}}}.a',
    f"abort {DEEP_ARRAY}",
    f"return {DEEP_ARRAY}",
    f"map_values(.) -> |v| {{ {DEEP_ARRAY} }}",
    "%a" + ".a" * 200 + " = 1",
    "x" + ".a" * 200 + " = 1",
])
def test_depth_check_sees_every_route(source):
    with pytest.raises(ValueError, match="levels deep, the limit is 128"):
        Transform(source)


def on_small_thread(function):
    """Calls `function` on a worker thread with a macOS-sized default stack."""
    outcome = []

    def target():
        try:
            outcome.append(function())
        except Exception as error:
            outcome.append(error)

    previous = threading.stack_size(512 * 1024)
    try:
        worker = threading.Thread(target=target)
        worker.start()
        worker.join()
    finally:
        threading.stack_size(previous)
    return outcome[0]


def dotted(levels):
    return {".".join(["a"] * levels): 1}

def xml(levels):
    return {"s": "<a>" * levels + "x" + "</a>" * levels}

def ruby(levels):
    return {"s": '{ "a" => ' * levels + "1" + " }" * levels}

# Each of these builds a value as deep as its input, then walks and drops it.
DEEP_DATA = {
    "unflatten": ("unflatten!(.)", dotted(20_000)),
    "set": ("set!({}, .p, 1)", {"p": ["a"] * 20_000}),
    "parse_xml": ("parse_xml!(.s)", xml(20_000)),
    "parse_ruby_hash": ("parse_ruby_hash!(.s)", ruby(3_000)),
    "compact": ("compact(unflatten!(.))", dotted(20_000)),
    "encode_json": ("encode_json(unflatten!(.))\n{}", dotted(20_000)),
}

@pytest.mark.parametrize("case", DEEP_DATA)
@pytest.mark.parametrize("call", [lambda f: f(), on_small_thread], ids=["main", "worker"])
def test_deep_value_built_from_data_does_not_crash(case, call):
    source, data = DEEP_DATA[case]
    program = Transform(f"x = {source}\ntrue") if "\n" not in source else Transform(source)
    assert call(lambda: program.remap(data)) in (True, {})

@pytest.mark.parametrize("case", ["unflatten", "set", "parse_xml", "parse_ruby_hash"])
def test_deep_output_built_from_data_raises_recursion_error(case):
    source, data = DEEP_DATA[case]
    with pytest.raises(RecursionError):
        Transform(source).remap(data)

def test_large_event_within_limit_accepted():
    text = "x" * 100_000
    assert run(".", {"a": text}) == {"a": text}

def test_event_past_size_limit_rejected():
    with pytest.raises(ValueError, match="event is too large"):
        run(".", {"a": "x" * (4 * 1024 * 1024 + 1)})

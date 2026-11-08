# pyVRL

Exposes Vector VRL to Python for fast, simple & unified transforms
## Installation

`pip install pyVRL`


## Use

Create an instance of pyvrl.Transform using the VRL program as the sole argument

Apply the program to data with the object's `remap` function

```
>>> from pyvrl import Transform
>>> data: dict = {"x": "foo"}
>>> vrl_program = '''
... .y = "bar"
... .x = upcase!(.x)
... .z = uuid_v7()
... .
... '''
>>> transform = Transform(vrl_program)
>>> output = transform.remap(data)
>>> print(output)
{'x': 'FOO', 'y': 'bar', 'z': '018f79d0-812b-7f90-bc74-85042e23db44'}
```

## Untrusted programs

A program can only transform its input. Functions that reach the network, the environment, the host name or files named by the program aren't available: `dns_lookup`, `encode_proto`, `get_env_var`, `get_hostname`, `http_request`, `parse_etld`, `parse_groks`, `parse_proto`, `reverse_dns` and `validate_json_schema`. Using one fails when the program compiles.

For a program you wrote yourself, pass `Transform(program, allow_host_access=True)`.

## Converting logs to OCSF

`pyvrl.ocsf` converts logs to [OCSF](https://schema.ocsf.io) 1.9.0 using YAML mappings. These are built in: `auth0`, `aws_cloudtrail`, `aws_guardduty`, `aws_vpc_flow` and `azure_signin`.

```
>>> from pyvrl.ocsf import Mapping
>>> mapping = Mapping.builtin("aws_guardduty")
>>> event = mapping.convert(finding)
```

Split batches into single events, and decompress logs in Python, before calling `convert`. VPC Flow records go in `message`. If they don't use the default format, list their columns in `log_format`, such as `{"message": line, "log_format": "version srcaddr dstaddr ..."}`.

| Situation | Result |
| --- | --- |
| No route matches the event | Raises `NoRouteError` |
| The mapping fails on the event, such as a bad timestamp | Raises `ValueError` |
| The output isn't valid OCSF | Logs a warning to the `pyvrl.ocsf` logger and returns the event |

Pass `on_invalid="raise"` to raise `InvalidEventError` instead of warning, or `on_invalid="ignore"` to skip validation, which is about three times faster.

### Writing a mapping

The first route whose `when` matches converts the event. Field values are VRL expressions, so literal strings need two sets of quotes. Numbers and booleans are plain values.

```yaml
# yaml-language-server: $schema=schemas/ocsf-mapping.schema.json
source: sshd
let:
  m: parse_regex!(.message, r'^(?P<result>Failed|Accepted) password for (?P<user>\S+)')
routes:
  - class: authentication
    fields:
      activity_id: 1
      severity_id: 1
      time: to_unix_timestamp(now(), unit: "milliseconds")
      status_id: 'if m.result == "Accepted" { 1 } else { 2 }'
      user:
        name: m.user
      service:
        name: '"sshd"'
      metadata:
        product:
          name: '"sshd"'
```

`Mapping.load("sshd.yaml")` checks every field, enum value and required field against OCSF, so mistakes fail when the mapping loads. It fills in `class_uid`, `class_name`, `category_uid`, `category_name`, `type_uid` and `metadata.version`. To use a field from an OCSF profile, list the profile under the route's `profiles`.

For autocomplete in VS Code, install the YAML extension from Red Hat and point the first line of your mapping at the schema. To write a copy of the schema:

```
python -m pyvrl.ocsf schema ocsf-mapping.schema.json
```

### Updating OCSF

`scripts/build_ocsf_data.py` explains how to rebuild the catalogue from a new OCSF release. Afterwards, regenerate `schemas/ocsf-mapping.schema.json` with the command above.

## Limits

Programs and values are limited to 128 levels of nesting, and events to 4 MiB (256 KiB on 32-bit platforms).

| Exceeded by | Raised by | Error |
| --- | --- | --- |
| A program | `Transform` | `ValueError` |
| An input or output value | `remap` | `RecursionError` |
| An event's size | `remap` | `ValueError` |

Functions such as `unflatten`, `set` and `parse_xml` can build values far deeper than this while a program runs. That is safe, but it uses memory, so run untrusted data under a memory limit.

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

## Limits

Programs and values are limited to 128 levels of nesting, and events to 4 MiB (256 KiB on 32-bit platforms).

| Exceeded by | Raised by | Error |
| --- | --- | --- |
| A program | `Transform` | `ValueError` |
| An input or output value | `remap` | `RecursionError` |
| An event's size | `remap` | `ValueError` |

Functions such as `unflatten`, `set` and `parse_xml` can build values far deeper than this while a program runs. That is safe, but it uses memory, so run untrusted data under a memory limit.

"""The OCSF catalogue: every class, object and field in the supported version."""

import functools
import gzip
import json
from pathlib import Path

OCSF_VERSION = "1.9.0"


@functools.lru_cache(maxsize=1)
def catalogue():
    path = Path(__file__).parent / "data" / f"ocsf-{OCSF_VERSION}.json.gz"
    return json.loads(gzip.decompress(path.read_bytes()))


@functools.lru_cache(maxsize=1)
def classes_by_uid():
    return {item["uid"]: name for name, item in catalogue()["classes"].items()}


def base_type(type_name):
    return catalogue()["types"].get(type_name, type_name)

"""Run `python -m pyvrl.ocsf schema FILE` to write the editor schema for mappings."""

import sys

from .editor import write_mapping_schema


def main(arguments):
    if len(arguments) != 2 or arguments[0] != "schema":
        print(__doc__, file=sys.stderr)
        return 2
    write_mapping_schema(arguments[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

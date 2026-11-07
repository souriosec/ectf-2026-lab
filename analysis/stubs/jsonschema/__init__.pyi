"""Type interface for the jsonschema call used by the container normalizer.

This is a partial static interface, not a runtime implementation. The scanner
image supplies jsonschema; Windows/WSL host checks need no runtime installation.
"""

def validate(instance: object, schema: object) -> None: ...

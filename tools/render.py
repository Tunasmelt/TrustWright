"""Typed, injection-safe rendering of pack test templates.

Values come from the security intent, which an agent can write. Rendered output is
executed as Python. So no value is ever pasted into source text: strings become
escaped Python literals via repr(), and every other type must match a strict pattern.
The rendered module must parse, and its top-level shape must match the template's.
"""
from __future__ import annotations

import ast
import re

PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

TYPES = {
    # name: (validator, emitter). Emitters only ever produce a literal or a checked token.
    "python_string": (lambda v: isinstance(v, str), repr),
    "identifier": (lambda v: isinstance(v, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", v) is not None, str),
    "module_path": (lambda v: isinstance(v, str)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}(\.[A-Za-z_][A-Za-z0-9_]{0,63}){0,7}", v) is not None, str),
    "http_method": (lambda v: v in {"get", "post", "put", "patch", "delete", "head", "options"}, str),
    "http_status": (lambda v: isinstance(v, int) and not isinstance(v, bool) and 100 <= v <= 599, str),
}


class RenderError(ValueError):
    pass


def placeholders(template: str) -> set[str]:
    return set(PLACEHOLDER.findall(template))


def _shape(source: str) -> list[str]:
    """Top-level statement kinds: injected statements change this."""
    return [type(node).__name__ for node in ast.parse(source).body]


def render(template: str, declared: dict[str, str], values: dict) -> str:
    used = placeholders(template)
    if used != set(declared):
        raise RenderError(f"template placeholders {sorted(used)} != declared {sorted(declared)}")
    if set(values) != set(declared):
        raise RenderError(f"values {sorted(values)} != declared {sorted(declared)}")
    emitted = {}
    for name, kind in declared.items():
        if kind not in TYPES:
            raise RenderError(f"placeholder {name}: unknown type {kind!r}")
        valid, emit = TYPES[kind]
        if not valid(values[name]):
            raise RenderError(f"placeholder {name}: {values[name]!r} is not a valid {kind}")
        emitted[name] = emit(values[name])
    source = PLACEHOLDER.sub(lambda m: emitted[m.group(1)], template)
    try:
        rendered_shape = _shape(source)
    except SyntaxError as e:
        raise RenderError(f"rendered test does not parse: {e.msg}") from None
    # Reference shape: the same template rendered with inert values of each type.
    inert = {"python_string": "x", "identifier": "x", "module_path": "x", "http_method": "get", "http_status": 200}
    reference = PLACEHOLDER.sub(lambda m: TYPES[declared[m.group(1)]][1](inert[declared[m.group(1)]]), template)
    if rendered_shape != _shape(reference):
        raise RenderError("rendered test has a different top-level structure than the template (injected statements?)")
    return source

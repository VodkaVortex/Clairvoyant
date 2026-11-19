"""C function-span helper copied from the original family_detectors.py; heuristic, not a C parser."""

from __future__ import annotations

import bisect

import re

from dataclasses import dataclass

@dataclass(frozen=True)
class FunctionUnit:
    path: str
    name: str
    line_start: int
    line_end: int
    source: str
    masked_source: str

def mask_noncode(source: str) -> str:
    """Replace comments and literals with spaces while preserving newlines."""
    chars = list(source)
    state = "code"
    index = 0
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if char == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if char == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if char == '"':
                chars[index] = " "
                state = "string"
            elif char == "'":
                chars[index] = " "
                state = "char"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if char == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char != "\n":
                chars[index] = " "
        else:
            if char == "\\" and following:
                chars[index] = chars[index + 1] = " "
                index += 2
                continue
            terminator = '"' if state == "string" else "'"
            if char == terminator:
                chars[index] = " "
                state = "code"
            elif char != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)

def extract_functions(path: str, source: str) -> list[FunctionUnit]:
    """Extract ordinary C function definitions with stable source line spans."""
    masked = mask_noncode(source)
    stack: list[int] = []
    closing: dict[int, int] = {}
    for index, char in enumerate(masked):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            closing[stack.pop()] = index + 1
    newlines = [match.start() for match in re.finditer("\n", source)]
    line_of = lambda position: bisect.bisect_right(newlines, position) + 1
    pattern = re.compile(
        r"(?m)^[ \t]*(?:[A-Za-z_]\w*\s+|\*\s*)*"
        r"([A-Za-z_]\w*)\s*\([^;{}]*?\)\s*\{"
    )
    units: list[FunctionUnit] = []
    control_keywords = {"if", "for", "while", "switch", "do", "else"}
    for match in pattern.finditer(masked):
        if match.group(1) in control_keywords:
            continue
        opening = match.end() - 1
        end = closing.get(opening)
        if end is None:
            continue
        units.append(FunctionUnit(
            path=path,
            name=match.group(1),
            line_start=line_of(match.start()),
            line_end=line_of(max(end - 1, match.start())),
            source=source[match.start():end],
            masked_source=masked[match.start():end],
        ))
    return units

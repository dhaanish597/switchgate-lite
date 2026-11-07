#!/usr/bin/env python3
"""AST & line-count guardrail checker for SwitchGate Lite (Document C lessons)."""
import ast
import pathlib
import sys

MAX_FILE_LINES = 250
MAX_FUNC_LINES = 40
MIN_TOOLS = 3


def main() -> int:
    root = pathlib.Path(__file__).resolve().parent.parent
    src_dir = root / "src"
    errors = []
    has_bounded_loop = False
    tool_count = 0

    for path in sorted(src_dir.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        if len(lines) > MAX_FILE_LINES:
            errors.append(f"{path.name}: {len(lines)} lines exceeds max {MAX_FILE_LINES}")
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > MAX_FUNC_LINES:
                    errors.append(f"{path.name}:{node.name} is {length} lines (max {MAX_FUNC_LINES})")
                for dec in node.decorator_list:
                    if "tool" in ast.unparse(dec):
                        tool_count += 1
            elif isinstance(node, ast.While):
                cond = ast.unparse(node.test)
                if "turn" in cond and "max_turns" in cond:
                    has_bounded_loop = True

    if not has_bounded_loop:
        errors.append("Missing bounded `while turn < max_turns` loop in src/")
    if tool_count < MIN_TOOLS:
        errors.append(f"Found {tool_count} @tool definitions (expected >= {MIN_TOOLS})")

    if errors:
        print("GUARDRAIL CHECK FAILED:")
        for e in errors:
            print(f" - {e}")
        return 1
    print(f"GUARDRAIL CHECK PASSED: all files <= {MAX_FILE_LINES} lines, all funcs <= {MAX_FUNC_LINES} lines, {tool_count} @tools, bounded loop verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

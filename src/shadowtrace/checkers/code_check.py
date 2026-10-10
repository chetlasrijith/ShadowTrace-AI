"""Sandboxed code checker for the code family.

Generated code is untrusted by definition, so it never runs in the pilot
process. It runs in a fresh interpreter with a timeout, a clean environment,
no arguments, and a scratch working directory. Network access is not
explicitly firewalled here: the generated snippets are short helpers with no
imports, and any import statement is rejected before execution. Documented
limitation, adequate for the pilot.
"""

from __future__ import annotations

import ast
import re
import subprocess
import sys
import tempfile
from pathlib import Path


def extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return text.strip()


def structural_check(code: str, fn_name: str) -> tuple[bool, str]:
    """Parseable Python with the required function defined?"""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return False, f"SyntaxError: {e}"
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    if fn_name not in names:
        return False, f"required function {fn_name} not defined"
    banned = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            banned.update(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom):
            banned.add(n.module or "")
    banned.discard("")
    if banned:
        return False, f"imports rejected in sandbox: {sorted(banned)}"
    return True, ""


def run_tests(code: str, tests: list[str], timeout_s: float = 10.0) -> tuple[bool, str]:
    """Execute reference-plus-tests in a subprocess. Returns (passed, log)."""
    script = code + "\n\n" + "\n".join(tests) + "\nprint('ALL_TESTS_PASSED')\n"
    with tempfile.TemporaryDirectory(prefix="shadowtrace_code_") as tmp:
        try:
            proc = subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True, text=True, timeout=timeout_s,
                cwd=tmp, env={"PATH": "", "SYSTEMROOT": "", "PYTHONHASHSEED": "0"},
            )
        except subprocess.TimeoutExpired:
            return False, f"timeout after {timeout_s}s"
    ok = proc.returncode == 0 and "ALL_TESTS_PASSED" in proc.stdout
    log = (proc.stdout + proc.stderr)[-2000:]
    return ok, log


def score_code(model_output: str, fn_name: str, tests: list[str]) -> dict:
    code = extract_code(model_output)
    valid, valid_err = structural_check(code, fn_name)
    if not valid:
        return {
            "task_success": False, "structural_valid": False,
            "structural_error": valid_err, "code": code[:500],
        }
    passed, log = run_tests(code, tests)
    return {
        "task_success": passed, "structural_valid": True,
        "structural_error": "", "test_log": log[-500:],
    }
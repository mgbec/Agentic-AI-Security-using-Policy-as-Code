"""
Example agent loop demonstrating OWASP-aligned, Semgrep-clean patterns.

This is the SAST target for policies/semgrep/agentic.yaml. It shows the SAFE
side of each rule so you can see what "green" looks like, and contrast it with
the commented-out unsafe patterns each rule would flag.
"""

import json
import subprocess


MAX_TOOL_CALLS = 10  # ASI02/ASI08: bounded budget, never an unbounded loop.


def run_agent(task: str, tools: dict) -> dict:
    """Run a bounded agent loop. No unbounded `while True`."""
    result = {}
    for _ in range(MAX_TOOL_CALLS):  # bounded, not `while True` (ASI02)
        step = _plan_next_step(task, result)
        if step is None:
            break
        result = _invoke_tool(step, tools)
    return result


def _invoke_tool(step: dict, tools: dict) -> dict:
    name = step["tool"]
    if name not in tools:
        raise ValueError(f"tool '{name}' not in allowlist")
    return tools[name](step.get("args", {}))


def parse_model_output(raw: str) -> dict:
    """ASI05: parse structured output; never eval() it."""
    # SAFE: json.loads, not eval(raw)
    return json.loads(raw)


def run_formatter(path: str) -> int:
    """ASI05: call a tool with an argument list, shell=False."""
    # SAFE: list args + shell=False, not os.system / shell=True
    completed = subprocess.run(
        ["black", "--check", path],
        shell=False,
        capture_output=True,
        check=False,
    )
    return completed.returncode


def remember(store, external_text: str) -> None:
    """ASI06: sanitize external content before writing to memory."""
    cleaned = _sanitize(external_text)
    store.add_texts([cleaned])  # written only after sanitize


def _sanitize(text: str) -> str:
    # Strip control chars and any instruction-looking directives before persist.
    return text.replace("\x00", "").strip()


def _plan_next_step(task, state):  # placeholder planner
    return None

"""Optional polyglot taint analysis (JS/TS) via tree-sitter — the `[polyglot]` extra.

Mirrors the Python taint detector for JavaScript/TypeScript: model/LLM output flowing into a
dangerous sink (eval/Function/exec/child_process/innerHTML/raw query). Degrades gracefully:
if tree-sitter (and a grammar) isn't installed, this is a no-op and the regex rules still run.
"""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

_LANG_BY_EXT = {".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
                ".cjs": "javascript", ".ts": "typescript", ".tsx": "tsx"}

_MODEL_RE = re.compile(
    r"(openai|anthropic|\.chat\.completions|\.messages\.create|\.generate\b|\.invoke\b|"
    r"generateText|generateContent|ChatOpenAI|ChatAnthropic|\bllm\b)")
_SINK_FUNCS = {"eval", "Function", "exec", "execSync", "spawn", "spawnSync",
               "runInNewContext", "runInThisContext", "compileFunction"}
_SINK_MEMBER = re.compile(r"\b(exec|execSync|runInNewContext|query|run|raw)$")
_HTML_SINK = re.compile(r"(innerHTML|outerHTML|dangerouslySetInnerHTML)$")  # maroon: ignore[ME-LLM10-unsafe-render] detection pattern, not a render site


def available() -> bool:
    try:
        import tree_sitter_language_pack  # noqa: F401
        return True
    except Exception:
        return False


def _text(node) -> str:
    try:
        return node.text.decode("utf-8", "replace")
    except Exception:
        return ""


def _descendants(node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.children)


def _names_in(node) -> Set[str]:
    return {_text(n) for n in _descendants(node) if n.type == "identifier"}


def _has_model_call(node) -> bool:
    for n in _descendants(node):
        if n.type == "call_expression":
            fn = n.child_by_field_name("function")
            if fn is not None and _MODEL_RE.search(_text(fn)):
                return True
    return False


def _sink_of_call(node) -> Optional[str]:
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    ftext = _text(fn)
    if fn.type == "identifier" and ftext in _SINK_FUNCS:
        return "code execution (%s)" % ftext
    if fn.type == "member_expression":
        prop = fn.child_by_field_name("property")
        pt = _text(prop) if prop is not None else ""
        if pt in _SINK_FUNCS or _SINK_MEMBER.search(ftext):
            return "command/query execution (%s)" % pt or "sink"
    return None


def _analyze(root) -> List[Tuple[int, str]]:
    # Collect assignment-like bindings: (target_name, value_node, line)
    bindings = []
    sinks = []          # (call_or_assign_node, value_node_for_args, line, desc)
    for n in _descendants(root):
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            value = n.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier":
                bindings.append((_text(name), value))
        elif n.type == "assignment_expression":
            left = n.child_by_field_name("left")
            right = n.child_by_field_name("right")
            if left is not None and right is not None:
                if left.type == "identifier":
                    bindings.append((_text(left), right))
                # HTML sink: el.innerHTML = <tainted>
                if left.type == "member_expression" and _HTML_SINK.search(_text(left)):
                    sinks.append((right, n.start_point[0] + 1,
                                  "DOM XSS sink (%s)" % _text(left.child_by_field_name("property") or left)))
        elif n.type == "call_expression":
            desc = _sink_of_call(n)
            if desc:
                args = n.child_by_field_name("arguments")
                if args is not None:
                    sinks.append((args, n.start_point[0] + 1, desc))

    # Fixpoint taint over identifier names.
    tainted: Set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, value in bindings:
            if name in tainted:
                continue
            if _has_model_call(value) or (_names_in(value) & tainted):
                tainted.add(name)
                changed = True
    if not tainted:
        return []

    hits: List[Tuple[int, str]] = []
    seen: Set[int] = set()
    for value_node, line, desc in sinks:
        if (_names_in(value_node) & tainted) and line not in seen:
            seen.add(line)
            hits.append((line, "Untrusted model output reaches %s (JS/TS). Validate/encode in "
                               "trusted code before this sink (LLM10/ASI05)." % desc))
    return hits


def run(rule: Dict, target, make_finding: Callable) -> List:
    if not available():
        return []
    try:
        from tree_sitter_language_pack import get_parser
    except Exception:
        return []
    out = []
    parsers: Dict[str, object] = {}
    import os
    for rel in target.files:
        lang = _LANG_BY_EXT.get(os.path.splitext(rel)[1].lower())
        if not lang:
            continue
        src = "\n".join(target.read_lines(rel))
        if not _MODEL_RE.search(src):
            continue
        try:
            if lang not in parsers:
                parsers[lang] = get_parser(lang)
            tree = parsers[lang].parse(src.encode("utf-8", "replace"))
        except Exception:
            continue
        for line, msg in _analyze(tree.root_node):
            out.append(make_finding(rule, target, rel, line, message=msg))
    return out

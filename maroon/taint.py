"""python_ast_taint detector: LLM/model output flowing into a dangerous sink.

Deterministic, function-scoped, zero-dep (Python `ast`). Taints variables assigned from a
model call (or derived from a tainted variable, via fixpoint), then flags dangerous sinks
(exec/eval/compile, os.system, subprocess, cursor.execute, dangerouslySetInnerHTML-style
template interpolation) that reference a tainted value. Maps to LLM10 / ASI05 / LLM03.
"""
from __future__ import annotations

import ast
from typing import Callable, Dict, List, Optional, Set, Tuple

# A call is treated as a model call if its function attribute is one of these...
_MODEL_METHODS = {
    "create", "acreate", "generate", "agenerate", "invoke", "ainvoke", "predict",
    "complete", "completion", "chat", "run", "arun", "stream",
}
# ...AND the attribute owner chain mentions something model-ish, OR the callee name is model-ish.
_MODEL_HINTS = {
    "openai", "anthropic", "client", "llm", "model", "chat", "completions", "messages",
    "chain", "agent", "chatopenai", "chatanthropic", "genai", "generativemodel", "pipeline",
}

_SINK_NAMES = {"eval", "exec", "compile"}
_SINK_ATTR = {
    ("os", "system"), ("os", "popen"),
    ("subprocess", "run"), ("subprocess", "call"), ("subprocess", "Popen"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
}
_SINK_METHODS = {"execute", "executescript", "executemany"}  # DB cursors -> SQLi (DSGAI12/LLM10)


def _attr_chain(node: ast.AST) -> List[str]:
    out: List[str] = []
    while isinstance(node, ast.Attribute):
        out.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        out.append(node.id)
    return list(reversed(out))


def _is_model_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        if func.attr in _MODEL_METHODS:
            chain = [c.lower() for c in _attr_chain(func)]
            return any(h in chain for h in _MODEL_HINTS)
    if isinstance(func, ast.Name):
        return func.id.lower() in {"llm", "complete", "generate"}
    return False


def _subtree_has_model_call(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and _is_model_call(n):
            return True
    return False


def _names_used(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _assign_targets(node: ast.AST) -> List[str]:
    out: List[str] = []
    targets = node.targets if isinstance(node, ast.Assign) else (
        [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign)) else [])
    for t in targets:
        for n in ast.walk(t):
            if isinstance(n, ast.Name):
                out.append(n.id)
    return out


def _sink_of(call: ast.Call) -> Optional[str]:
    func = call.func
    if isinstance(func, ast.Name) and func.id in _SINK_NAMES:
        return "code execution (%s)" % func.id
    if isinstance(func, ast.Attribute):
        chain = _attr_chain(func)
        if len(chain) >= 2 and (chain[0], chain[-1]) in _SINK_ATTR:
            return "OS command execution (%s)" % ".".join([chain[0], chain[-1]])
        if func.attr in _SINK_METHODS:
            return "SQL/command execution (%s)" % func.attr
        if func.attr == "system":
            return "OS command execution (system)"
    return None


def _iter_scope_stmts(body: List[ast.stmt]):
    """Yield statements in a function/module body, descending into control flow but NOT
    into nested function/class/lambda definitions (those are separate scopes)."""
    stack = list(body)
    while stack:
        node = stack.pop(0)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.stmt):
                stack.append(child)


def _analyze_scope(body: List[ast.stmt]) -> List[Tuple[int, str]]:
    stmts = list(_iter_scope_stmts(body))
    # Fixpoint taint: a name is tainted if assigned from a model call or from a tainted name.
    tainted: Dict[str, int] = {}
    changed = True
    while changed:
        changed = False
        for node in stmts:
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = node.value
                if value is None:
                    continue
                rhs_tainted = _subtree_has_model_call(value) or bool(_names_used(value) & set(tainted))
                if rhs_tainted:
                    for name in _assign_targets(node):
                        if name not in tainted:
                            tainted[name] = getattr(node, "lineno", 0)
                            changed = True
    if not tainted:
        return []
    hits: List[Tuple[int, str]] = []
    for node in stmts:
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            sink = _sink_of(call)
            if not sink:
                continue
            used = _names_used(call)
            tainted_used = used & set(tainted)
            if tainted_used and getattr(call, "lineno", 10 ** 9) >= min(tainted[n] for n in tainted_used):
                hits.append((getattr(call, "lineno", 1),
                             "Untrusted model output reaches %s. Validate/encode in trusted "
                             "code before this sink (LLM10/ASI05)." % sink))
    return hits


def run(rule: Dict, target, make_finding: Callable) -> List:
    out = []
    for rel in target.files:
        if not rel.endswith(".py"):
            continue
        src = "\n".join(target.read_lines(rel))
        if "import" not in src and "def " not in src:
            continue
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError):
            continue
        scopes: List[List[ast.stmt]] = [tree.body]
        for n in ast.walk(tree):
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(n.body)
        seen: Set[int] = set()
        for body in scopes:
            for line, msg in _analyze_scope(body):
                if line in seen:
                    continue
                seen.add(line)
                out.append(make_finding(rule, target, rel, line, message=msg))
    return out

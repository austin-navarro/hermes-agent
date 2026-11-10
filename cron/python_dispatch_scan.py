"""Conservative reference-discovery view for a simple, concrete Python CLI dispatch.

Not an evaluator or a permission exemption. The caller still scans the ORIGINAL
source for lifecycle commands, charges its full budget, and uses the ordinary
bounded reader for every remaining reference. Unknown shapes return None.
"""
from __future__ import annotations

import ast
import copy
import logging
import symtable
from typing import TypeGuard

logger = logging.getLogger(__name__)
_UNKNOWN = object()
_REFLECTION = frozenset({'eval', 'exec', 'globals', 'locals', 'vars', 'getattr', 'setattr', 'delattr', '__import__'})


def _argv(node: ast.AST) -> TypeGuard[ast.Attribute]:
    return isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'sys' and node.attr == 'argv'


def _literal_strings(node):
    if isinstance(node, ast.List):
        values = []
        for item in node.elts:
            if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
                return _UNKNOWN
            values.append(item.value)
        return values
    return _UNKNOWN


def _guard_value(node, argv):
    """Only the standard main guard and literal sys.argv slices; never eval()."""
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        for part in node.values:
            value = _guard_value(part, argv)
            if value is _UNKNOWN:
                return _UNKNOWN
            if value is False:
                return False
        return True
    if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
        return _UNKNOWN
    left, right = node.left, node.comparators[0]
    if isinstance(left, ast.Name) and left.id == '__name__' and isinstance(right, ast.Constant):
        return right.value == '__main__'
    if isinstance(left, ast.Subscript) and _argv(left.value) and isinstance(left.slice, ast.Slice):
        sl = left.slice
        # argv[0] is invocation-dependent. Never substitute a fabricated script
        # name into a guard that could inspect it.
        if not isinstance(sl.lower, ast.Constant) or type(sl.lower.value) is not int or sl.lower.value < 1:
            return _UNKNOWN
        if sl.step is not None and not (isinstance(sl.step, ast.Constant) and type(sl.step.value) is int and sl.step.value > 0):
            return _UNKNOWN
        bounds = [x.value if isinstance(x, ast.Constant) and type(x.value) is int else None for x in (sl.lower, sl.upper, sl.step)]
        if any(x is not None and not (isinstance(x, ast.Constant) and type(x.value) is int) for x in (sl.lower, sl.upper, sl.step)):
            return _UNKNOWN
        value = _literal_strings(right)
        if value is not _UNKNOWN:
            return argv[slice(*bounds)] == value
    return _UNKNOWN


def _selected_body(function, argv):
    args = function.args
    if len(args.args) != 1 or args.posonlyargs or args.vararg or args.kwarg or args.kwonlyargs or args.defaults:
        return None
    body = function.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]
    if len(body) != 1 or not isinstance(body[0], ast.If):
        return None
    branch = body[0]
    while isinstance(branch, ast.If):
        test = branch.test
        if not (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
                and isinstance(test.left, ast.Name) and test.left.id == args.args[0].arg):
            return None
        option = _literal_strings(test.comparators[0])
        if option is _UNKNOWN:
            return None
        if option == argv:
            # One direct local operation. Only status has a fixed literal-argument form.
            if len(branch.body) != 1 or not isinstance(branch.body[0], ast.Expr):
                return None
            call = branch.body[0].value
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.keywords:
                return None
            if call.args:
                if argv != ['status'] or len(call.args) != 3:
                    return None
                for arg, expected in zip(call.args, ('status', '--short', '--branch')):
                    if not (isinstance(arg, ast.Constant) and type(arg.value) is str and arg.value == expected):
                        return None
            return call
        if len(branch.orelse) != 1:
            return None
        branch = branch.orelse[0]
    return None


def _module_functions(source, tree):
    # Compiler tables cover def/class, exception targets, imports and pattern
    # captures; merely looking for ast.Name(Store) misses those binding forms.
    symbols = symtable.symtable(source, '<lifecycle-scan>', 'exec')
    if '__name__' in symbols.get_identifiers():
        symbol = symbols.lookup('__name__')
        if symbol.is_assigned() or symbol.is_imported():
            return None
    if 'sys' in symbols.get_identifiers() and symbols.lookup('sys').is_assigned():
        return None
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    if len(functions) != sum(isinstance(n, ast.FunctionDef) for n in tree.body):
        return None
    if any(symbols.lookup(name).is_imported() or len(symbols.lookup(name).get_namespaces()) != 1 for name in functions):
        return None
    return functions


def _top_level_context(tree, argv):
    top, ignored, permitted_argv = [], set(), set()
    for node in tree.body:
        if isinstance(node, ast.If):
            known = _guard_value(node.test, ['<unknown argv0>', *argv])
            if known is not _UNKNOWN:
                permitted_argv.update(id(x) for x in ast.walk(node.test) if _argv(x))
                for dead in (node.orelse if known else node.body):
                    ignored.update(id(x) for x in ast.walk(dead))
                top.extend(node.body if known else node.orelse)
                continue
        top.append(node)
    return top, ignored, permitted_argv


def _entry_argv(call):
    if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Subscript):
        return None
    arg = call.args[0]
    if not (_argv(arg.value) and isinstance(arg.slice, ast.Slice) and isinstance(arg.slice.lower, ast.Constant)
            and type(arg.slice.lower.value) is int and arg.slice.lower.value == 1
            and arg.slice.upper is None and arg.slice.step is None):
        return None
    return arg.value


def _entry_call(top):
    entries = [n.value for n in top if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
               and isinstance(n.value.func, ast.Name) and n.value.func.id == 'main']
    if len(entries) != 1 or _entry_argv(entries[0]) is None:
        return None
    return entries[0]


def _contains_argv(node):
    return any(_argv(child) for child in ast.walk(node))


def _argv_identity_stable(node, parent, permitted_argv):
    if _argv(node) and (id(node) not in permitted_argv or not isinstance(node.ctx, ast.Load)):
        return False
    if isinstance(node, ast.Attribute) and node.attr == 'argv' and not _argv(node):
        return False
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == 'sys':
        if not (isinstance(parent, ast.Attribute) and parent.value is node
                and parent.attr in {'argv', 'executable', 'flags', 'path', 'stdout', 'stderr', 'version_info', 'platform', 'exit'}):
            return False
    if isinstance(node, (ast.Subscript, ast.Attribute)) and isinstance(node.ctx, (ast.Store, ast.Del)) and _contains_argv(node):
        return False
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and _argv(node.func.value):
        return False
    if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value is not None and _contains_argv(node.value):
        return False
    if isinstance(node, ast.Call) and any(_argv(arg) for arg in node.args):
        return False
    return True


def _imports_stable(node, functions):
    if isinstance(node, ast.ImportFrom) and node.module == 'sys' and any(alias.name in {'argv', '*'} for alias in node.names):
        return False
    for alias in node.names:
        bound = alias.asname or alias.name.split('.')[0]
        if alias.name == '*' or bound in (set(functions) | {'__name__'}):
            return False
        if alias.name == 'sys' and alias.asname not in {None, 'sys'}:
            return False
        if bound == 'sys' and not (isinstance(node, ast.Import) and alias.name == 'sys'):
            return False
    return True


def _namespace_stable(node, functions, entry, protected):
    # Re-entry, aliases and callbacks could invoke main with different argv.
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id == 'main' and node is not entry.func:
        return False
    if isinstance(node, ast.Attribute) and node.attr == 'main':
        return False
    if isinstance(node, ast.FunctionDef) and node.decorator_list:
        return False
    if isinstance(node, (ast.Import, ast.ImportFrom)) and not _imports_stable(node, functions):
        return False
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return False
    if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and node.id in protected:
        return False
    return True


def _identities_stable(nodes, functions, main, entry, ignored, permitted_argv):
    parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
    protected = set(functions) | {'sys', '__name__', main.args.args[0].arg}
    for node in nodes:
        if id(node) in ignored:
            continue
        if not _argv_identity_stable(node, parents.get(id(node)), permitted_argv):
            return False
        if not _namespace_stable(node, functions, entry, protected):
            return False
    return True


def _reachable_functions(top, functions):
    # Keep definition-time expressions even for functions never called.
    roots = []
    for node in top:
        if isinstance(node, ast.FunctionDef):
            header = copy.deepcopy(node)
            header.body = [ast.Pass()]
            roots.append(header)
        else:
            roots.append(node)
    reachable, pending = set(), list(roots)
    while pending:
        for node in ast.walk(pending.pop()):
            if isinstance(node, ast.Attribute) and (node.attr.startswith('__') or node.attr in {'f_globals', 'f_locals', 'f_back', 'tb_frame', 'gi_frame', 'ag_frame', 'cr_frame'}):
                return None
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ''
                if name in _REFLECTION:
                    return None
            name = node.id if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) else node.attr if isinstance(node, ast.Attribute) else None
            if name in functions and name not in reachable:
                reachable.add(name)
                pending.extend(functions[name].body)
    return reachable


def _project(tree, selected, argv):
    projected = copy.deepcopy(tree)
    functions = {n.name: n for n in projected.body if isinstance(n, ast.FunctionDef)}
    functions['main'].body = [ast.Expr(value=copy.deepcopy(selected))]
    top, _, _ = _top_level_context(projected, argv)
    if _entry_call(top) is None:
        return None
    reachable = _reachable_functions(top, functions)
    if reachable is None:
        return None
    for name, node in functions.items():
        if name not in reachable:
            node.body = [ast.Pass()]
    projected.body = top
    ast.fix_missing_locations(projected)
    return ast.unparse(projected)


def python_dispatch_view(source: str, argv: list[str]) -> str | None:
    """Return a reference-only view, or None for any ambiguous/dynamic form.

    The caller establishes direct Python execution and provides the concrete
    argv tail. This intentionally does not apply to shell/Python polyglots,
    interpreter command strings, callbacks, or arbitrary dispatch frameworks.
    """
    try:
        tree = ast.parse(source)
        nodes = list(ast.walk(tree))
        if len(nodes) > 12000:
            return None
        functions = _module_functions(source, tree)
        if functions is None:
            return None
        main = functions.get('main')
        if main is None or main.decorator_list:
            return None
        selected = _selected_body(main, argv)
        if selected is None or not isinstance(selected.func, ast.Name) or selected.func.id not in functions:
            return None
        top, ignored, permitted_argv = _top_level_context(tree, argv)
        entry = _entry_call(top)
        if entry is None:
            return None
        permitted_argv.add(id(_entry_argv(entry)))
        if not _identities_stable(nodes, functions, main, entry, ignored, permitted_argv):
            return None
        return _project(tree, selected, argv)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # Expected parser/resource failures retain full recursion without logging
        # source-bearing parser exceptions.
        return None
    except Exception:
        logger.exception('Unexpected Python dispatch projection failure; retaining full scan')
        return None

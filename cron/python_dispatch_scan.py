"""Conservative reference-discovery view for a simple, concrete Python CLI dispatch.

Not an evaluator or a permission exemption. The caller still scans the ORIGINAL
source for lifecycle commands, charges its full budget, and uses the ordinary
bounded reader for every remaining reference. Unknown shapes return None.
"""
from __future__ import annotations

import ast
import copy
import symtable
from typing import TypeGuard

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


def _dispatch_match(test, name, argv):
    """Recognize only literal list equality or a fixed-arity, indexed verb."""
    match test:
        case ast.Compare(left=ast.Name(id=left), ops=[ast.Eq()], comparators=[right]) if left == name:
            option = _literal_strings(right)
            return _UNKNOWN if option is _UNKNOWN else option == argv
        case ast.BoolOp(op=ast.And(), values=[
            ast.Compare(left=ast.Call(func=ast.Name(id='len'), args=[ast.Name(id=left)], keywords=[]),
                        ops=[ast.Eq()], comparators=[ast.Constant(value=count)]),
            ast.Compare(left=ast.Subscript(value=ast.Name(id=right), slice=ast.Constant(value=index)),
                        ops=[ast.Eq()], comparators=[ast.Constant(value=verb)]),
        ]) if (left == right == name and type(count) is int and type(index) is int
               and 0 <= index < count and isinstance(verb, str)):
            return len(argv) == count and argv[index] == verb
    return _UNKNOWN


def _dispatch_argument(node, name, argv):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == name
            and isinstance(node.slice, ast.Constant) and type(node.slice.value) is int
            and 0 <= node.slice.value < len(argv)):
        return ast.copy_location(ast.Constant(value=argv[node.slice.value]), node)
    return None


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
        match = _dispatch_match(branch.test, args.args[0].arg, argv)
        if match is _UNKNOWN:
            return None
        if match:
            # Preserve concrete operand strings in the reference view, including
            # script paths passed as argv values; never erase them as mere data.
            if len(branch.body) != 1 or not isinstance(branch.body[0], ast.Expr):
                return None
            call = branch.body[0].value
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.keywords:
                return None
            values = []
            for argument in call.args:
                value = _dispatch_argument(argument, args.args[0].arg, argv)
                if value is None:
                    return None
                values.append(value)
            selected = copy.deepcopy(call)
            selected.args = values
            return selected
        if len(branch.orelse) != 1:
            return None
        branch = branch.orelse[0]
    return None


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
        # Compiler symbol tables cover ALL binding forms (def/class, exception
        # targets, imports, pattern captures), not just ast.Name(Store). These
        # module identities are assumptions of the concrete-dispatch proof.
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
            return None  # class/function collisions or imported replacements
        main = functions.get('main')
        if main is None or main.decorator_list:
            return None
        selected = _selected_body(main, argv)
        if selected is None or not isinstance(selected.func, ast.Name) or selected.func.id not in functions:
            return None
        # len() must be the builtin, and the dispatcher parameter cannot shadow
        # the selected callable. Defaults/variadics would require a wider binder.
        parameter = main.args.args[0].arg
        if parameter in functions or parameter == 'len':
            return None
        for scope in (symbols, symbols.lookup('main').get_namespaces()[0]):
            if 'len' in scope.get_identifiers():
                binding = scope.lookup('len')
                if binding.is_assigned() or binding.is_imported() or binding.is_parameter():
                    return None
        target_args = functions[selected.func.id].args
        if (target_args.posonlyargs or target_args.vararg or target_args.kwarg
                or target_args.kwonlyargs or target_args.defaults
                or len(target_args.args) != len(selected.args)):
            return None
        # Allow sys.argv only at the one validated entry call or in fully
        # understood top-level guards. Defaults, keyword arguments and other
        # escapes can mutate it before the entry point is reached.
        top_original = []
        ignored = set()
        permitted_argv = set()
        for n in tree.body:
            if isinstance(n, ast.If):
                known = _guard_value(n.test, ['<unknown argv0>', *argv])
                if known is not _UNKNOWN:
                    permitted_argv.update(id(x) for x in ast.walk(n.test) if _argv(x))
                    for dead in (n.orelse if known else n.body):
                        ignored.update(id(x) for x in ast.walk(dead))
                    top_original.extend(n.body if known else n.orelse)
                    continue
            top_original.append(n)
        entries = [n.value for n in top_original if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                   and isinstance(n.value.func, ast.Name) and n.value.func.id == 'main']
        if len(entries) != 1:
            return None
        entry = entries[0]
        if len(entry.args) != 1 or entry.keywords or not isinstance(entry.args[0], ast.Subscript):
            return None
        arg = entry.args[0]
        if not (_argv(arg.value) and isinstance(arg.slice, ast.Slice) and isinstance(arg.slice.lower, ast.Constant)
                and type(arg.slice.lower.value) is int and arg.slice.lower.value == 1
                and arg.slice.upper is None and arg.slice.step is None):
            return None
        permitted_argv.add(id(arg.value))
        parents = {id(child): parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        # Rebinding, argv mutation/aliasing, and namespace writes defeat this proof.
        for n in nodes:
            if id(n) in ignored:
                continue
            if _argv(n) and id(n) not in permitted_argv:
                return None
            if isinstance(n, ast.Attribute) and n.attr == 'argv' and not _argv(n):
                return None
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == 'sys':
                parent = parents.get(id(n))
                if not (isinstance(parent, ast.Attribute) and parent.value is n
                        and parent.attr in {'argv', 'executable', 'flags', 'path', 'stdout', 'stderr', 'version_info', 'platform', 'exit'}):
                    return None  # the module itself escaped; aliases can mutate argv
            # Recursion/re-entry could pass different argv to the projected
            # dispatcher. Aliases and callbacks are just as ambiguous.
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id == 'main' and n is not entry.func:
                return None
            if isinstance(n, ast.Attribute) and n.attr == 'main':
                return None
            if isinstance(n, ast.FunctionDef) and n.decorator_list:
                return None
            if isinstance(n, ast.Name) and n.id == '__builtins__':
                return None  # the len builtin's namespace may escape or mutate
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                if isinstance(n, ast.ImportFrom) and n.module == 'builtins':
                    return None
                if isinstance(n, ast.ImportFrom) and n.module == 'sys' and any(alias.name in {'argv', '*'} for alias in n.names):
                    return None
                for alias in n.names:
                    bound = alias.asname or alias.name.split('.')[0]
                    if alias.name == '*' or alias.name == 'builtins' or bound in (set(functions) | {'__name__'}) or (alias.name == 'sys' and alias.asname not in {None, 'sys'}) or (bound == 'sys' and not (isinstance(n, ast.Import) and alias.name == 'sys')):
                        return None
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                return None
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)) and n.id in (set(functions) | {'sys', '__name__', main.args.args[0].arg}):
                return None
            if isinstance(n, (ast.Subscript, ast.Attribute)) and isinstance(n.ctx, (ast.Store, ast.Del)) and any(_argv(x) for x in ast.walk(n)):
                return None
            if _argv(n) and not isinstance(n.ctx, ast.Load):
                return None
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and _argv(n.func.value):
                return None
            if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and n.value is not None and any(_argv(x) for x in ast.walk(n.value)):
                return None
            if isinstance(n, ast.Call) and any(_argv(arg) for arg in n.args):
                return None
        # Keep definition-time expressions even for functions never called.
        projected = copy.deepcopy(tree)
        projected_functions = {n.name: n for n in projected.body if isinstance(n, ast.FunctionDef)}
        projected_functions['main'].body = [ast.Expr(value=copy.deepcopy(selected))]
        # Keep every concrete operand eligible for the existing bounded reader,
        # even a suffixless relative script supplied through a parameter. These
        # are reference-only mentions, not executable statements or exemptions.
        projected_functions['main'].body.extend(
            ast.Expr(value=ast.Constant(value=value.value if '/' in value.value else './' + value.value))
            for value in selected.args
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value
        )
        top = []
        main_calls = 0
        for n in projected.body:
            if isinstance(n, ast.If):
                known = _guard_value(n.test, ['<script>', *argv])
                if known is False:
                    top.extend(n.orelse)
                    continue
                if known is True:
                    top.extend(n.body)
                    continue
            top.append(n)
        for n in top:
            if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name) and n.value.func.id == 'main':
                call = n.value
                if len(call.args) != 1 or call.keywords or not isinstance(call.args[0], ast.Subscript):
                    return None
                arg = call.args[0]
                if not (_argv(arg.value) and isinstance(arg.slice, ast.Slice) and isinstance(arg.slice.lower, ast.Constant)
                        and arg.slice.lower.value == 1 and arg.slice.upper is None and arg.slice.step is None):
                    return None
                main_calls += 1
        if main_calls != 1:
            return None
        # References to a local function include aliases, containers and callbacks,
        # not just Call(Name(...)); ambiguous references retain the entire function.
        roots = []
        for n in top:
            if isinstance(n, ast.FunctionDef):
                header = copy.deepcopy(n)
                header.body = [ast.Pass()]
                roots.append(header)
            else:
                roots.append(n)
        reachable = set()
        pending = list(roots)
        while pending:
            node = pending.pop()
            for n in ast.walk(node):
                if isinstance(n, ast.Attribute) and (n.attr.startswith('__') or n.attr in {'f_globals', 'f_locals', 'f_back', 'tb_frame', 'gi_frame', 'ag_frame', 'cr_frame'}):
                    return None
                if isinstance(n, ast.Call):
                    name = n.func.id if isinstance(n.func, ast.Name) else n.func.attr if isinstance(n.func, ast.Attribute) else ''
                    if name in _REFLECTION:
                        return None
                name = n.id if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) else n.attr if isinstance(n, ast.Attribute) else None
                if name in functions and name not in reachable:
                    reachable.add(name)
                    pending.extend(projected_functions[name].body)
        for name, n in projected_functions.items():
            if name not in reachable:
                n.body = [ast.Pass()]
        projected.body = top
        ast.fix_missing_locations(projected)
        return ast.unparse(projected)
    except Exception:
        # Never let parser/resource errors reach the outer guard's direct-only
        # exception fallback: retain the original full recursive scan instead.
        return None

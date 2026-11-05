"""Concrete CLI dispatch must not scan an unrelated Python operation's helpers.

These tests only scan text; they never execute a fixture or touch production data.
"""
import shlex

import pytest

from cron import lifecycle_guard as guard


def _runner(tmp_path):
    target = tmp_path / 'unrelated-operator'
    target.write_text('x' * (2 * 1024 * 1024))
    runner = tmp_path / 'runner.py'
    runner.write_text(
        '#!/usr/bin/env python3\nimport sys, subprocess\nfrom pathlib import Path\n'
        'def test():\n    print("sandbox test")\n'
        'def migrate():\n'
        f'    helper = Path({str(target)!r})\n'
        '    subprocess.run([sys.executable, str(helper)])\n'
        'def main(argv):\n'
        '    if argv == ["test"]:\n        test()\n'
        '    elif argv == ["migrate"]:\n        migrate()\n'
        '    else:\n        raise SystemExit(2)\n'
        'if __name__ == "__main__":\n    main(sys.argv[1:])\n'
    )
    return runner, target


def _parameterized_runner(tmp_path):
    data = tmp_path / 'unrelated-data'
    data.write_bytes(b'x' * (2 * 1024 * 1024))
    helper = tmp_path / 'migration-helper.py'
    helper.write_text(f'from pathlib import Path\nDATABASE = Path({str(data)!r})\n')
    runner = tmp_path / 'parameterized.py'
    runner.write_text(
        '#!/usr/bin/env python3\nimport sys, subprocess\nfrom pathlib import Path\n'
        'def check():\n    print("check")\n'
        'def commit(release):\n    print(release)\n'
        'def install(release):\n    print(release)\n'
        'def migrate():\n'
        f'    helper = Path({str(helper)!r})\n'
        '    subprocess.run([sys.executable, str(helper)])\n'
        'def main(argv):\n'
        '    if argv == ["test"]:\n        check()\n'
        '    elif len(argv) == 2 and argv[0] == "commit":\n        commit(argv[1])\n'
        '    elif len(argv) == 2 and argv[0] == "install":\n        install(argv[1])\n'
        '    elif argv == ["migrate"]:\n        migrate()\n'
        '    else:\n        raise SystemExit(2)\n'
        'if __name__ == "__main__":\n    main(sys.argv[1:])\n'
    )
    return runner, helper, data


def test_parameterized_install_does_not_read_unselected_helper_or_data(tmp_path, monkeypatch):
    runner, helper, data = _parameterized_runner(tmp_path)
    reads = []
    reader = guard._read_referenced_script

    def record(path, **kwargs):
        reads.append(path)
        return reader(path, **kwargs)

    monkeypatch.setattr(guard, '_read_referenced_script', record)
    actual = guard.scan_gateway_lifecycle(f'{shlex.quote(str(runner))} install release', cwd=str(tmp_path))
    assert actual == (False, None), {'actual': actual, 'reads': [str(path) for path in reads]}
    assert runner in reads
    assert helper not in reads
    assert data not in reads


@pytest.mark.parametrize('operand', ['argv[1]', '"fixed-release"'])
def test_parameterized_literal_and_indexed_arguments_select_branch(tmp_path, operand):
    runner, _, _ = _parameterized_runner(tmp_path)
    runner.write_text(runner.read_text().replace('install(argv[1])', f'install({operand})'))
    assert guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path)) == (False, None)


def test_parameterized_selected_executable_helper_still_blocks(tmp_path):
    runner, _, data = _parameterized_runner(tmp_path)
    runner.write_text(runner.read_text().replace(
        'def install(release):\n    print(release)',
        f'def install(release):\n    helper = Path({str(data)!r})\n'
        '    subprocess.run([sys.executable, str(helper)])',
    ))
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('operand_kind', ['absolute', 'relative', 'bare'])
def test_parameterized_argv_executable_is_not_erased(tmp_path, monkeypatch, operand_kind):
    runner, helper, data = _parameterized_runner(tmp_path)
    runner.write_text(runner.read_text().replace(
        'def install(release):\n    print(release)',
        'def install(release):\n    subprocess.run([sys.executable, release])',
    ))
    reads = []
    reader = guard._read_referenced_script

    def record(path, **kwargs):
        reads.append(path)
        return reader(path, **kwargs)

    monkeypatch.setattr(guard, '_read_referenced_script', record)
    operand = {'absolute': str(data), 'relative': './' + data.name, 'bare': data.name}[operand_kind]
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install {operand}', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal
    assert data in reads
    assert helper not in reads


@pytest.mark.parametrize('operation', ['install', 'migrate'])
def test_parameterized_literal_lifecycle_in_any_body_stays_blocked(tmp_path, operation):
    runner, _, _ = _parameterized_runner(tmp_path)
    source = runner.read_text()
    insertion = '    subprocess.run("hermes gateway restart", shell=True)\n'
    if operation == 'install':
        source = source.replace('def install(release):\n', 'def install(release):\n' + insertion)
    else:
        source = source.replace('def migrate():\n', 'def migrate():\n' + insertion)
    runner.write_text(source)
    assert guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path)) == (True, None)


@pytest.mark.parametrize('condition', [
    'choose(argv)',
    'len(argv) != 2 and argv[0] == "install"',
    'len(argv) == 2 or argv[0] == "install"',
    'len(argv) == True and argv[0] == "install"',
    'len(argv) == 2 and argv[-1] == "install"',
    'len(argv) == 2 and argv[2] == "install"',
    'len(argv) == 2 and argv[True] == "install"',
])
def test_parameterized_ambiguous_predicates_retain_full_scan(tmp_path, condition):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('len(argv) == 2 and argv[0] == "install"', condition)
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('call', [
    'install(argv[-1])', 'install(argv[2])', 'install(argv[True])',
    'install(argv[1:])', 'install(choose(argv))', 'install(*argv[1:])',
    'install(release=argv[1])', 'dispatch[argv[0]](argv[1])',
])
def test_parameterized_unknown_operands_retain_full_scan(tmp_path, call):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('install(argv[1])', call)
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('signature', [
    'release="default"', '*release', 'release, /', '*, release', 'release, other', '',
])
def test_parameterized_unsupported_binding_retain_full_scan(tmp_path, signature):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('def install(release):', f'def install({signature}):')
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('mutation', [
    'len = lambda value: 2\n', 'from unknown import len\n',
    'import builtins\nbuiltins.len = lambda value: 2\n',
    '__builtins__["len"] = lambda value: 2\n',
    'install = migrate\n', 'sys.argv[1] = "migrate"\n',
    'alias = sys.argv\nalias.append("migrate")\n',
])
def test_parameterized_shadow_or_mutation_retains_full_scan(tmp_path, mutation):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('if __name__ == "__main__":', mutation + 'if __name__ == "__main__":')
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('parameter', ['len', 'install'])
def test_parameterized_dispatch_parameter_cannot_shadow_proof_names(tmp_path, parameter):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('argv', parameter).replace(f'sys.{parameter}', 'sys.argv')
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('body', ['main(["migrate"])', 'globals()["install"]()', 'alias = main\n    alias(["migrate"])'])
def test_parameterized_reflection_reentry_and_callback_retain_full_scan(tmp_path, body):
    from cron.python_dispatch_scan import python_dispatch_view
    runner, _, data = _parameterized_runner(tmp_path)
    source = runner.read_text().replace('def install(release):\n    print(release)', f'def install(release):\n    {body}')
    runner.write_text(source)
    assert python_dispatch_view(source, ['install', 'release']) is None
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


@pytest.mark.parametrize('prefix', ['env ', 'timeout 30 ', 'bash '])
def test_parameterized_wrappers_keep_full_scan(tmp_path, prefix):
    runner, _, data = _parameterized_runner(tmp_path)
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{prefix}{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


def test_parameterized_unselected_definition_default_is_still_scanned(tmp_path):
    runner, _, data = _parameterized_runner(tmp_path)
    runner.write_text(runner.read_text().replace('def migrate():', f'def migrate(argument=Path({str(data)!r})):'))
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} install release', cwd=str(tmp_path))
    assert unsafe and refusal is not None and str(data) in refusal


def test_exact_dispatch_does_not_read_unselected_helper(tmp_path, monkeypatch):
    runner, target = _runner(tmp_path)
    reads = []
    reader = guard._read_referenced_script
    def record(path, **kwargs):
        reads.append(path)
        return reader(path, **kwargs)
    monkeypatch.setattr(guard, '_read_referenced_script', record)
    assert guard.scan_gateway_lifecycle(f'{shlex.quote(str(runner))} test', cwd=str(tmp_path)) == (False, None)
    assert runner in reads
    assert target not in reads


@pytest.mark.parametrize('prefix', ['', 'env ', 'timeout 30 '])
def test_selected_unscannable_helper_still_blocks(tmp_path, prefix):
    runner, target = _runner(tmp_path)
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{prefix}{shlex.quote(str(runner))} migrate', cwd=str(tmp_path))
    assert unsafe is True
    assert refusal is not None and 'scan cap' in refusal and str(target) in refusal


def test_literal_gateway_command_keeps_conservative_block(tmp_path):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('print("sandbox test")', 'subprocess.run("hermes gateway restart", shell=True)'))
    assert guard.scan_gateway_lifecycle(f'{shlex.quote(str(runner))} test', cwd=str(tmp_path)) == (True, None)


@pytest.mark.parametrize('mutation', [
    'sys.argv[1] = "migrate"\n',
    'sys.argv = [sys.argv[0], "migrate"]\n',
    'globals()["test"] = migrate\n',
    'test = migrate\n',
    'getattr(sys, "argv")[1] = "migrate"\n',
])
def test_mutated_dispatch_falls_back_to_full_scan(tmp_path, mutation):
    runner, _ = _runner(tmp_path)
    text = runner.read_text()
    runner.write_text(text.replace('if __name__ == "__main__":', mutation + 'if __name__ == "__main__":'))
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{shlex.quote(str(runner))} test', cwd=str(tmp_path))
    assert unsafe is True
    assert refusal is not None


def test_shell_dispatch_is_not_pruned_as_python(tmp_path):
    target = tmp_path / 'oversized'
    target.write_text('x' * (2 * 1024 * 1024))
    runner = tmp_path / 'runner.sh'
    runner.write_text(f'#!/bin/sh\nbash {shlex.quote(str(target))}\n')
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('mutation', [
    'sys.argv.append("migrate")\n',
    'other = sys.argv\nother[1] = "migrate"\n',
    'from unknown import test\n',
    'test.__globals__["test"] = migrate\n',
])
def test_alias_reflection_and_import_rebinding_retain_full_scan(tmp_path, mutation):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('if __name__ == "__main__":', mutation + 'if __name__ == "__main__":'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


def test_unknown_condition_side_effect_before_false_is_not_discarded(tmp_path):
    runner, _ = _runner(tmp_path)
    text = runner.read_text().replace('if __name__ == "__main__":',
        'if migrate() and sys.argv[1:2] == ["not-test"]:\n    pass\nif __name__ == "__main__":')
    runner.write_text(text)
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('call', ['migrate()', 'alias = migrate\n    alias()', 'callbacks = {"x": migrate}\n    callbacks["x"]()', 'migrate(\n    )'])
def test_reachable_function_aliases_keep_helper_scan(tmp_path, call):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('print("sandbox test")', call))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


def test_function_decorator_does_not_allow_projection(tmp_path):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('def test():', '@unknown_decorator\ndef test():'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


def test_definition_time_default_is_still_scanned(tmp_path):
    runner, target = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('def migrate():', f'def migrate(argument=Path({str(target)!r})):'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


def test_explicit_shell_interpretation_never_uses_python_projection(tmp_path):
    runner, _ = _runner(tmp_path)
    assert guard.scan_gateway_lifecycle(f'bash {runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('exception', [ValueError, RecursionError, MemoryError])
def test_parser_exception_retains_recursive_scan(tmp_path, monkeypatch, exception):
    from cron import python_dispatch_scan
    runner, _ = _runner(tmp_path)
    def fail(*args, **kwargs):
        raise exception('synthetic parser failure')
    monkeypatch.setattr(python_dispatch_scan.ast, 'parse', fail)
    unsafe, refusal = guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))
    assert unsafe and refusal is not None and 'scan cap' in refusal


def test_direct_literal_scan_is_not_limited_to_reachable_functions(tmp_path):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('def migrate():', 'def never_called():\n    return "hermes gateway restart"\ndef migrate():'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path)) == (True, None)


@pytest.mark.parametrize('reference', ['main(["migrate"])', 'again = main\n    again(["migrate"])', 'sys.modules[__name__].main(["migrate"])'])
def test_dispatcher_reentry_cannot_reuse_initial_argv(tmp_path, reference):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('print("sandbox test")', reference))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('mutation', [
    'def mutate(args):\n    args[1] = "migrate"\nmutate(args=sys.argv)\n',
    'def mutate(args=sys.argv):\n    args[1] = "migrate"\nmutate()\n',
])
def test_sys_argv_keyword_and_default_escapes_fall_back(tmp_path, mutation):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('if __name__ == "__main__":', mutation + 'if __name__ == "__main__":'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('slice_text', [':1', '0:1', '1::-1'])
def test_unknown_runtime_argv0_is_never_used_to_prune(tmp_path, slice_text):
    runner, _ = _runner(tmp_path)
    condition = f'if sys.argv[{slice_text}] == [{str(runner)!r}]:\n    migrate()\n'
    runner.write_text(runner.read_text().replace('if __name__ == "__main__":', condition + 'if __name__ == "__main__":'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


def test_tuple_comparison_does_not_match_list_argv(tmp_path):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('if argv == ["test"]:\n        test()', 'if argv == ("test",):\n        test()\n    elif argv == ["test"]:\n        migrate()'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('mutation', [
    'def mutate(module):\n    module.argv[1] = "migrate"\nmutate(sys)\n',
    'import os\nos.sys.argv[1] = "migrate"\n',
    'from unknown import *\n',
])
def test_sys_module_escape_and_star_import_fall_back(tmp_path, mutation):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('if __name__ == "__main__":', mutation + 'if __name__ == "__main__":'))
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True


@pytest.mark.parametrize('binding', [
    'def __name__():\n    pass\n',
    'class __name__:\n    pass\n',
    'try:\n    raise ValueError()\nexcept ValueError as __name__:\n    pass\n',
    'match "changed":\n    case __name__:\n        pass\n',
    'class sys:\n    pass\n',
    'class main:\n    pass\n',
])
def test_compiler_binding_forms_invalidate_dispatch_identity(tmp_path, binding):
    runner, _ = _runner(tmp_path)
    runner.write_text(runner.read_text().replace('if __name__ == "__main__":', binding + 'if __name__ == "__main__":') + 'else:\n    migrate()\n')
    assert guard.scan_gateway_lifecycle(f'{runner} test', cwd=str(tmp_path))[0] is True

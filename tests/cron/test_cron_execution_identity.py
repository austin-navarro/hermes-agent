"""Plugins can tell which cron execution they run inside (#130722)."""
import json
import os
import subprocess
import sys
import textwrap
import pytest
from datetime import timedelta
from pathlib import Path

from tests.fakes.fake_llm_provider import FakeLLMServer, Text, ToolCall, write_hermes_home

_PLUGIN = '''
import dataclasses, json, os
from pathlib import Path

CTX = None

def _record(**kwargs):
    ident = CTX.current_cron_execution()
    out = Path(os.environ["HERMES_HOME"]) / "seen.json"
    out.write_text(json.dumps({"tool": kwargs.get("tool_name"),
                               "identity": dataclasses.asdict(ident) if ident else None}))

def register(ctx):
    global CTX
    CTX = ctx
    ctx.register_hook("pre_tool_call", _record)
'''

_TICK = '''
import json, sys
from cron import scheduler, scheduler_authority
from cron.executions import list_executions
from tests.cron.conftest import owner_execution_runner
# Cron executes inside the profile's owner; run the owner's execution seam in-process.
scheduler_authority.run_canonical_job = owner_execution_runner()
from hermes_cli.plugins import get_plugin_manager
scheduler.tick(verbose=False, sync=True)
ctx = get_plugin_manager()._plugins["cron-identity-probe"].module.CTX
print(json.dumps({"outside": ctx.current_cron_execution(), "profile": ctx.profile_name,
                  "executions": list_executions(job_id="probe")}, default=str))
'''


_ROOT = Path(__file__).resolve().parents[2]
_CHAIN_ORIGINAL = """\
import importlib.machinery
import importlib.util
rest = [p for p in sys.path if os.path.abspath(p or os.curdir) != C['startup']]
spec = importlib.machinery.PathFinder.find_spec('sitecustomize', rest)
if spec is not None and spec.loader is not None:
    original_site = importlib.util.module_from_spec(spec)
    sys.modules['_cron_original_sitecustomize'] = original_site
    spec.loader.exec_module(original_site)
"""
_STARTUP_BEFORE_CHAIN = r"""
import os, sys, json, io, hashlib
from pathlib import Path


def redact_path(text):
    text = text.split('?', 1)[0].split('#', 1)[0]
    if text == C['denied']:
        return '<TEST_HOME>/.startup-denied'
    prefixes = [(C['root'], '<CHECKOUT>'), (C['home'], '<TEST_HOME>'),
                (C['prefix'], '<TEST_VENV>')]
    prefixes += [(root, '<PROTECTED_HOME:%d>' % i) for i, root in enumerate(C['roots'])]
    for prefix, label in sorted(prefixes, key=lambda row: len(row[0]), reverse=True):
        if text == prefix or text.startswith(prefix + os.sep):
            return (label + text[len(prefix):])[:128]
    return text[:96] if text.startswith('<') else '<OTHER_PATH>'

def denial_detail(value):
    text = os.fsdecode(value) if isinstance(value, (str, bytes, Path)) else '<' + type(value).__name__ + '>'
    result = dict(target_id=hashlib.sha256(text.encode('utf-8', 'backslashreplace')).hexdigest()[:16],
                  target=redact_path(text), metadata=None, destructive=None, operation='unknown', frames=[])
    frame = sys._getframe(1)
    try:
        for _ in range(12):
            if frame is None:
                break
            code = frame.f_code
            if code.co_filename.endswith('/tests/home_io_guard.py'):
                if code.co_name == 'check':
                    for key in ('metadata', 'destructive'):
                        flag = frame.f_locals.get(key)
                        result[key] = flag if isinstance(flag, bool) else None
                elif code.co_name == 'guarded':
                    original = frame.f_locals.get('original')
                    name = getattr(original, '__name__', '')
                    result['operation'] = ('io.open' if name == 'observed_io_open' else name)[:32]
                elif code.co_name == 'guarded_open':
                    result['operation'] = 'os.open'
            elif code.co_filename != __file__ and len(result['frames']) < 3:
                result['frames'].append(dict(file=redact_path(code.co_filename)[:80],
                                             function=code.co_name[:32], line=frame.f_lineno))
            frame = frame.f_back
    finally:
        del frame
    return result

def emit(kind, detail=None):
    path = Path(C['witness'])
    if path.exists() and path.stat().st_size > 32768:
        raise SystemExit('cron startup witness full')
    argv = sys.orig_argv
    mode = '-m' if '-m' in argv else ('-c' if '-c' in argv else 'script')
    module = argv[argv.index('-m') + 1] if mode == '-m' else ''
    record = dict(kind=kind, pid=os.getpid(), ppid=os.getppid(), mode=mode, module=module)
    if detail is not None:
        record.update(detail)
    data = json.dumps(record).encode() + b'\n'
    if len(data) > 1024:
        raise SystemExit('cron startup witness oversized')
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)

def validate():
    argv = sys.orig_argv
    script = Path(C['home']) / 'scripts' / 'effect.py'
    effect_script = argv == [sys.executable, str(script)]
    direct = len(argv) >= 3 and argv[0] == sys.executable and argv[1] in ('-c', '-m')
    if not (effect_script or direct):
        raise SystemExit('cron startup unexpected invocation')
    if effect_script and (script.parent.is_symlink() or script.is_symlink() or not script.is_file()):
        raise SystemExit('cron startup unexpected effect script')
    expected_path = C['startup'] if effect_script else os.pathsep.join([C['startup'], C['root']])
    if (os.environ.get('HOME') != C['home']
            or os.environ.get('USERPROFILE') != C['home']
            or os.environ.get('HERMES_HOME') != C['home']
            or os.environ.get('HERMES_TEST_ISOLATION') != C['home']
            or os.environ.get('HERMES_DISABLE_LAZY_INSTALLS') != '1'
            or 'HERMES_STATE_DB_GUARD_BYPASS' in os.environ
            or os.environ.get('PYTHONPATH') != expected_path
            or sys.prefix != C['prefix'] or sys.prefix == sys.base_prefix
            or sys.flags.isolated or sys.flags.no_site or sys.flags.ignore_environment):
        raise SystemExit('cron startup isolation mismatch')

try:
    validate()
    if 'hermes_bootstrap' in sys.modules:
        raise SystemExit('cron startup ran after bootstrap')
    from pytest import MonkeyPatch
    script_only = sys.orig_argv == [sys.executable, str(Path(C['home']) / 'scripts' / 'effect.py')]
    if script_only:
        import importlib.util
        guard_path = Path(C['root']) / 'tests' / 'home_io_guard.py'
        if hashlib.sha256(guard_path.read_bytes()).hexdigest() != C['guard_sha256']:
            raise SystemExit('cron startup original guard changed')
        guard_spec = importlib.util.spec_from_file_location('_cron_original_home_io_guard', str(guard_path))
        if guard_spec is None or guard_spec.loader is None or guard_spec.origin != str(guard_path):
            raise SystemExit('cron startup original guard origin mismatch')
        guard_module = importlib.util.module_from_spec(guard_spec)
        previous_bytecode = sys.dont_write_bytecode
        try:
            sys.dont_write_bytecode = True
            guard_spec.loader.exec_module(guard_module)
        finally:
            sys.dont_write_bytecode = previous_bytecode
        HomeIOGuard = guard_module.HomeIOGuard
        if (guard_module.__file__ != str(guard_path)
                or HomeIOGuard.check.__code__.co_filename != str(guard_path)
                or Path(C['root']) not in guard_module._INTERPRETER_PREFIXES):
            raise SystemExit('cron startup original guard identity mismatch')
    else:
        from tests.home_io_guard import HomeIOGuard
    patcher = MonkeyPatch()
    raw_io_open = io.open
    def observed_io_open(file, *args, **kwargs):
        if not isinstance(file, int) and os.fspath(file) == C['denied']:
            emit('underlying-synthetic-open')
        return raw_io_open(file, *args, **kwargs)
    patcher.setattr(io, 'open', observed_io_open)
    guard = HomeIOGuard(lambda: C['roots'], lambda: C['apps'])
    def refuse(value):
        try:
            emit('denied', denial_detail(value))
        except BaseException:
            # Only observer failures are caught; the actual refusal below is unconditional.
            try:
                os.write(2, b'CRON_DENIAL_LOG_FAILED\n')
            except BaseException:
                pass
        finally:
            HomeIOGuard.refuse(value)
    guard.refuse = refuse
    guard.install(patcher)
    guarded_io_open = io.open
    guarded_os_open = os.open
    if not script_only:
        from pm import environments
        original_reader = environments._payload_manifest
        original_owner = environments.owning_home_root
        def nonpayload(root):
            validate()
            if Path(root).resolve() != Path(C['root']):
                raise SystemExit('cron startup unexpected payload root')
            return None
        patcher.setattr(environments, '_payload_manifest', nonpayload)
        def nonowner(root):
            validate()
            if not isinstance(root, (str, Path)) or os.fspath(root) != C['root']:
                raise SystemExit('cron startup unexpected owner root')
            return None
        patcher.setattr(environments, 'owning_home_root', nonowner)
"""
_STARTUP_AFTER_CHAIN = r"""
    validate()
    if ((not script_only and (environments._payload_manifest is not nonpayload
                              or environments.owning_home_root is not nonowner))
            or io.open is not guarded_io_open or os.open is not guarded_os_open):
        raise SystemExit('original customization undid cron isolation')
    if script_only and (guard_module.__file__ != str(guard_path)
                        or HomeIOGuard is not guard_module.HomeIOGuard):
        raise SystemExit('original customization undid original guard identity')
    emit('ready')
except BaseException as exc:
    print('cron test startup failed: ' + type(exc).__name__, file=sys.stderr)
    raise SystemExit(97) from exc
"""


def _startup_text(home):
    import hashlib
    from tests import conftest
    home = home.resolve()
    startup = home / '.cron-startup'
    config = dict(home=str(home), startup=str(startup), root=str(_ROOT), prefix=sys.prefix,
                  guard_sha256=hashlib.sha256((_ROOT / 'tests' / 'home_io_guard.py').read_bytes()).hexdigest(),
                  witness=str(startup / 'witness.jsonl'), denied=str(home / '.startup-denied'),
                  roots=[str(p) for p in conftest._REAL_HERMES_ROOT_CANDIDATES]
                        + [str(home / '.startup-denied')],
                  apps=list(conftest._REAL_INSTALLED_GUI_APPS))
    return ('C = ' + repr(config) + '\n' + _STARTUP_BEFORE_CHAIN
            + textwrap.indent(_CHAIN_ORIGINAL, '    ') + _STARTUP_AFTER_CHAIN)


def _prepare_child_startup(home):
    directory = home.resolve() / '.cron-startup'
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    assert not directory.is_symlink() and directory.stat().st_uid == os.getuid()
    path = directory / 'sitecustomize.py'
    text = _startup_text(home)
    compile(text, str(path), 'exec')
    if path.exists():
        assert not path.is_symlink() and path.read_text() == text
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            out.write(text)
    return directory


def _validate_child_env(home, env):
    directory = home.resolve() / '.cron-startup'
    path = directory / 'sitecustomize.py'
    assert env['HERMES_HOME'] == env['HERMES_TEST_ISOLATION'] == str(home)
    assert env['HOME'] == env['USERPROFILE'] == str(home)
    assert env['HERMES_DISABLE_LAZY_INSTALLS'] == '1'
    assert 'HERMES_STATE_DB_GUARD_BYPASS' not in env
    assert env['PYTHONPATH'].split(os.pathsep) == [str(directory), str(_ROOT)]
    assert not directory.is_symlink() and directory.stat().st_uid == os.getuid()
    assert not path.is_symlink() and path.stat().st_uid == os.getuid()
    assert path.read_text() == _startup_text(home)
    compile(path.read_text(), str(path), 'exec')


def _startup_records(home):
    path = home / '.cron-startup' / 'witness.jsonl'
    if not path.exists():
        return []
    data = path.read_bytes()
    assert len(data) < 65536
    return [json.loads(line) for line in data.splitlines()]


def _assert_child_startups(home, previous, stderr=""):
    records = _startup_records(home)
    fresh = [r for r in records if r['pid'] not in previous]
    print('CRON_STARTUP_EVIDENCE ' + json.dumps(fresh, sort_keys=True))
    assert 'CRON_DENIAL_LOG_FAILED' not in stderr, stderr
    assert records and all(row['kind'] == 'ready' for row in records), records
    assert any(r['ppid'] == os.getpid() and r['mode'] == '-c' for r in fresh), fresh
    ready = {r['pid']: r for r in records}
    for ack in home.glob('*.ready'):
        row = ready[json.loads(ack.read_text())['pid']]
        assert row['mode'] == '-m' and row['module'] == 'cron.scheduler', row


def _child_env(home, parent=None):
    env = {k: v for k, v in (os.environ if parent is None else parent).items()
           if not k.startswith(("HERMES_", "_HERMES_"))
           and not k.endswith(("_API_KEY", "_TOKEN"))}
    startup = _prepare_child_startup(home)
    env.update(HERMES_HOME=str(home), PYTHONPATH=os.pathsep.join([str(startup), str(_ROOT)]))
    env.update(HERMES_DISABLE_LAZY_INSTALLS="1", HERMES_TEST_ISOLATION=str(home),
               HOME=str(home), USERPROFILE=str(home))
    return env


def test_child_env_contract(tmp_path):
    parent = {name: "synthetic-only" for name in (
        "OPENAI_API_KEY", "SERVICE_TOKEN", "HERMES_PROFILE",
        "_HERMES_SESSION_ID", "HERMES_STATE_DB_GUARD_BYPASS",
    )}
    parent.update(HERMES_HOME="unrelated-home", HERMES_TEST_ISOLATION="unrelated-marker",
                  HERMES_DISABLE_LAZY_INSTALLS="0", PATH="synthetic-path",
                  HOME="foreign-ordinary-home", USERPROFILE="foreign-user-profile")
    env = _child_env(tmp_path, parent)
    assert env["HERMES_HOME"] == str(tmp_path)
    assert env["HOME"] == env["USERPROFILE"] == str(tmp_path)
    assert env["HERMES_DISABLE_LAZY_INSTALLS"] == "1"
    assert env["HERMES_TEST_ISOLATION"] == str(tmp_path)
    assert env["PYTHONPATH"].split(os.pathsep) == [str(tmp_path / ".cron-startup"), str(_ROOT)]
    _validate_child_env(tmp_path, env)
    assert env["PATH"] == "synthetic-path"
    assert not set(parent).difference({"HERMES_HOME", "HERMES_TEST_ISOLATION",
                                      "HERMES_DISABLE_LAZY_INSTALLS", "PATH", "HOME", "USERPROFILE"}) & env.keys()




@pytest.mark.parametrize('mode', ['-c', '-m'])
def test_startup_benign_processes_are_armed(tmp_path, mode):
    from pm import environments
    parent_reader, parent_owner = environments._payload_manifest, environments.owning_home_root
    parent_env, parent_path = dict(os.environ), list(sys.path)
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    code = "import sitecustomize as s; from unittest.mock import patch; from pm import environments; from pathlib import Path; from hermes_constants import _get_platform_default_hermes_home\nassert Path.home() == Path(s.C['home'])\nassert _get_platform_default_hermes_home() == Path(s.C['home']) / '.hermes'\nwith patch.object(Path, 'read_text', side_effect=AssertionError('unexpected reader probe')), patch.object(Path, 'is_file', side_effect=AssertionError('unexpected owner probe')):\n assert environments._payload_manifest(Path(s.C['root'])) is None\n assert environments.owning_home_root(Path(s.C['root'])) is None\nprint('armed')"
    argv = [sys.executable, '-c', code] if mode == '-c' else [sys.executable, '-m', 'json.tool']
    result = subprocess.run(argv, input='{}' if mode == '-m' else '', env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    records = _startup_records(tmp_path)
    assert len(records) == 1 and records[0]['kind'] == 'ready' and records[0]['mode'] == mode
    assert environments._payload_manifest is parent_reader
    assert environments.owning_home_root is parent_owner
    assert dict(os.environ) == parent_env and sys.path == parent_path
    print('BENIGN_STARTUP_EVIDENCE ' + json.dumps(records, sort_keys=True))


@pytest.mark.parametrize('bad', ['home', 'marker', 'lazy', 'prefix', 'missing', 'broken',
                                'ordinary-home', 'user-profile'])
def test_startup_invalid_input_blocks_before_target(tmp_path, bad):
    env = _child_env(tmp_path)
    hook = tmp_path / '.cron-startup' / 'sitecustomize.py'
    if bad == 'home':
        env['HERMES_HOME'] = str(tmp_path / 'wrong')
    elif bad == 'marker':
        env['HERMES_TEST_ISOLATION'] = 'wrong'
    elif bad == 'lazy':
        env['HERMES_DISABLE_LAZY_INSTALLS'] = '0'
    elif bad == 'prefix':
        env['PYTHONPATH'] = str(_ROOT)
    elif bad == 'ordinary-home':
        env['HOME'] = 'foreign-ordinary-home'
    elif bad == 'user-profile':
        env['USERPROFILE'] = 'foreign-user-profile'
    elif bad == 'missing':
        hook.unlink()
    else:
        hook.write_text('invalid syntax (')
    # No unprotected Hermes target is launched for invalid startup inputs.
    with pytest.raises((AssertionError, OSError, SyntaxError)):
        _validate_child_env(tmp_path, env)
    assert _startup_records(tmp_path) == []


@pytest.mark.parametrize('change', ["raise RuntimeError('chain failed')",
                                    'environments._payload_manifest = original_reader',
                                    "os.environ['PYTHONPATH'] = 'lost'",
                                    'io.open = raw_io_open',
                                    'environments.owning_home_root = original_owner',
                                    "os.environ['HOME'] = 'lost'",
                                    "os.environ['USERPROFILE'] = 'lost'"])
def test_startup_loaded_chaining_failure_is_fatal(tmp_path, monkeypatch, change):
    monkeypatch.setattr(sys.modules[__name__], '_CHAIN_ORIGINAL', change + '\n')
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    result = subprocess.run([sys.executable, '-c', "print('BENIGN TARGET')"], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0 and 'BENIGN TARGET' not in result.stdout
    assert 'cron test startup failed' in result.stderr
    assert _startup_records(tmp_path) == []


@pytest.mark.parametrize('kind', ['wrong-root', 'guard', 'owner-root', 'owner-home'])
def test_startup_rejects_unexpected_lookup_before_open(tmp_path, kind):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    code = ("import sitecustomize as s; from pathlib import Path; from pm import environments; "
            + ("environments._payload_manifest(Path(s.C['home']))" if kind == 'wrong-root'
               else "environments.owning_home_root(Path(s.C['home']))" if kind == 'owner-root'
               else "s.os.environ['HOME'] = 'lost'; environments.owning_home_root(Path(s.C['root']))" if kind == 'owner-home'
               else "Path(s.C['denied']).read_text()"))
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0
    rows = _startup_records(tmp_path)
    assert rows[0]['kind'] == 'ready'
    if kind == 'guard':
        assert 'TEST BUG: file I/O' in result.stderr
        assert [r['kind'] for r in rows] == ['ready', 'denied']
        detail = rows[1]
        assert detail['target'] == '<TEST_HOME>/.startup-denied'
        assert len(detail['target_id']) == 16
        assert detail['metadata'] is False and detail['destructive'] is False
        assert detail['operation'] == 'io.open' and 0 < len(detail['frames']) <= 3
        assert all(set(f) == {'file', 'function', 'line'} for f in detail['frames'])
    else:
        assert ('unexpected payload root' if kind == 'wrong-root' else
                'unexpected owner root' if kind == 'owner-root' else
                'isolation mismatch') in result.stderr
        assert len(rows) == 1






def test_startup_observer_failure_preserves_original_denial(tmp_path):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    code = ("import sitecustomize as s; from pathlib import Path\n"
            "def broken_emit(*args, **kwargs):\n raise ValueError('synthetic observer failure')\n"
            "s.emit = broken_emit\nPath(s.C['denied']).read_text()")
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0
    assert 'CRON_DENIAL_LOG_FAILED' in result.stderr
    assert 'AssertionError: TEST BUG: file I/O' in result.stderr
    assert [r['kind'] for r in _startup_records(tmp_path)] == ['ready']




def test_startup_sanitized_effect_script_descendant(tmp_path):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'effect.py').write_text("print('benign effect-script probe')\n")
    code = ("import json, sitecustomize as s; from pathlib import Path; "
            "from cron.scheduler_script import _script_argv, _run_job_script; "
            "from tools.environments.local import build_subprocess_env; "
            "script = Path(s.C['home']) / 'scripts' / 'effect.py'; "
            "argv, overlay, error = _script_argv(script); assert error is None; "
            "child_env = build_subprocess_env(strip_launch_profile=True); child_env.update(overlay); "
            "print('SANITIZED_SCRIPT_ARGV ' + json.dumps(argv)); "
            "print('SANITIZED_SCRIPT_PYTHONPATH ' + json.dumps(child_env.get('PYTHONPATH'))); "
            "ok, output = _run_job_script(str(script)); assert ok, output; "
            "assert output == 'benign effect-script probe'")
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    print(result.stdout)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = _startup_records(tmp_path)
    assert len(rows) == 2 and all(r['kind'] == 'ready' for r in rows), rows




@pytest.mark.parametrize('bad', ['unknown-script', 'outside-script', 'extra-argument',
                                'extra-pythonpath', 'lost-marker', 'direct-missing-checkout',
                                'linked-script'])
def test_startup_sanitized_script_unknown_scope_is_fatal(tmp_path, bad):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    script = scripts / 'effect.py'
    script.write_text("print('BENIGN TARGET')\n")
    env['PYTHONPATH'] = str(tmp_path / '.cron-startup')
    argv = [sys.executable, str(script)]
    if bad in ('unknown-script', 'outside-script'):
        other = (scripts if bad == 'unknown-script' else tmp_path) / 'other.py'
        other.write_text("print('BENIGN TARGET')\n")
        argv[1] = str(other)
    elif bad == 'extra-argument':
        argv.append('unexpected')
    elif bad == 'extra-pythonpath':
        env['PYTHONPATH'] += os.pathsep + str(_ROOT)
    elif bad == 'lost-marker':
        env.pop('HERMES_TEST_ISOLATION')
    elif bad == 'direct-missing-checkout':
        argv = [sys.executable, '-c', "print('BENIGN TARGET')"]
    else:
        other = scripts / 'other.py'
        script.rename(other)
        script.symlink_to(other)
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode != 0 and 'BENIGN TARGET' not in result.stdout
    assert 'cron test startup failed' in result.stderr
    assert _startup_records(tmp_path) == []




def test_startup_sanitized_script_original_guard_before_open_and_fd(tmp_path):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    scripts = tmp_path / 'scripts'
    scripts.mkdir()
    (scripts / 'effect.py').write_text(
        "import os, sys, sitecustomize as s\nfrom pathlib import Path\n"
        "assert s.guard_module.__file__ == str(Path(s.C['root']) / 'tests' / 'home_io_guard.py')\n"
        "assert s.guard.__class__ is s.guard_module.HomeIOGuard\n"
        "assert Path(s.C['root']) in s.guard_module._INTERPRETER_PREFIXES\n"
        "assert str(Path(s.C['root'])) not in sys.path\n"
        "assert os.environ['PYTHONPATH'] == s.C['startup']\n"
        "assert 'tests' not in sys.modules and 'pm.environments' not in sys.modules\n"
        "r, w = os.pipe()\nwith os.fdopen(w, 'w') as out:\n out.write('owned')\n"
        "with os.fdopen(r) as inp:\n assert inp.read() == 'owned'\n"
        "print('FD_TRANSPARENT')\nPath(s.C['denied']).read_text()\n")
    code = ("import sitecustomize as s; from pathlib import Path; "
            "from cron.scheduler_script import _run_job_script; "
            "ok, output = _run_job_script(str(Path(s.C['home']) / 'scripts' / 'effect.py')); "
            "assert not ok and 'AssertionError: TEST BUG: file I/O' in output, output; "
            "assert 'FD_TRANSPARENT' in output, output")
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = _startup_records(tmp_path)
    assert [r['kind'] for r in rows] == ['ready', 'ready', 'denied'], rows
    assert rows[1]['mode'] == 'script' and rows[1]['ppid'] == rows[0]['pid']
    assert rows[2]['target'] == '<TEST_HOME>/.startup-denied'
    assert rows[2]['operation'] == 'io.open'


def test_startup_fdopen_passthrough(tmp_path):
    env = _child_env(tmp_path)
    _validate_child_env(tmp_path, env)
    code = "import os\nr, w = os.pipe()\nwith os.fdopen(w, 'w') as out:\n out.write('owned')\nwith os.fdopen(r) as inp:\n assert inp.read() == 'owned'"
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert [r['kind'] for r in _startup_records(tmp_path)] == ['ready']


def test_startup_reader_does_not_leak_without_prefix(tmp_path):
    env = _child_env(tmp_path)
    env['PYTHONPATH'] = str(_ROOT)
    checkout = tmp_path / 'plain'
    checkout.mkdir()
    code = ("from pathlib import Path; from pm import environments; "
            "assert environments._payload_manifest.__module__ == 'pm.environments'; "
            f"assert environments._payload_manifest(Path({str(checkout)!r})) is None; "
            "assert environments.owning_home_root.__module__ == 'pm.environments'; "
            f"assert environments.owning_home_root(Path({str(checkout)!r})) is None")
    result = subprocess.run([sys.executable, '-c', code], env=env,
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert _startup_records(tmp_path) == []


def test_tool_hook_in_a_ticked_job_sees_its_execution_and_none_outside(tmp_path):
    from hermes_time import now

    home = tmp_path / "home"
    plugin_dir = home / "plugins" / "cron-identity-probe"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.yaml").write_text("name: cron-identity-probe\nversion: 0.0.1\n")
    (plugin_dir / "__init__.py").write_text(_PLUGIN)
    note = home / "note.txt"
    with FakeLLMServer([ToolCall("read_file", {"path": str(note)}), Text("done")]) as srv:
        write_hermes_home(home, srv.base_url,
                          extra_config="plugins:\n  enabled: [cron-identity-probe]\n")
        note.write_text("hello\n")
        (home / "cron").mkdir()
        (home / "cron" / "jobs.json").write_text(json.dumps({"jobs": [{
            "id": "probe", "name": "identity probe", "prompt": "read the note",
            "schedule": {"kind": "interval", "minutes": 240},
            "next_run_at": (now() - timedelta(minutes=1)).isoformat(),
            "enabled": True, "state": "scheduled", "deliver": "local",
            "repeat": {"times": None, "completed": 0}}]}))
        env = _child_env(home)
        _validate_child_env(home, env)
        previous = {row['pid'] for row in _startup_records(home)}
        result = subprocess.run([sys.executable, "-c", _TICK], env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=180, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "preparing dependencies" not in result.stderr and "Installing Python dependencies" not in result.stderr, result.stderr
    _assert_child_startups(home, previous, result.stderr)
    report = json.loads(result.stdout.strip().splitlines()[-1])
    seen = json.loads((home / "seen.json").read_text())
    (execution,) = report["executions"]

    assert seen["tool"] == "read_file"
    ident = seen["identity"]
    assert ident is not None, "pre_tool_call fired inside a cron run saw no cron identity"
    assert ident["job_id"] == "probe"
    assert ident["job_name"] == "identity probe"
    assert ident["execution_id"] == execution["id"]
    assert ident["source"] == execution["source"] == "builtin"
    assert ident["scheduled_instant"] == execution["scheduled_instant"] is not None
    assert ident["started_at"] == execution["started_at"]
    assert ident["profile"] == report["profile"]
    assert report["outside"] is None


def test_identity_is_scoped_and_not_inherited_by_delegated_children():
    from agent.delegation_context import delegated_child_context
    from cron.execution_identity import (
        current_cron_execution, enter_cron_execution, exit_cron_execution)

    record = {"source": "builtin", "scheduled_instant": None, "started_at": "2026-10-04T00:00:00"}
    assert current_cron_execution() is None
    token = enter_cron_execution({"id": "j", "name": "J"}, "exec-1", record)
    try:
        assert current_cron_execution().execution_id == "exec-1"
        with delegated_child_context("child"):
            assert current_cron_execution() is None
    finally:
        exit_cron_execution(token)
    assert current_cron_execution() is None

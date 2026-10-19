"""Tests for cronjob no_agent mode — script-driven jobs that skip the LLM.

Covers:

* ``create_job(no_agent=True)`` shape, validation, and serialization.
* ``cronjob(action='create', no_agent=True)`` tool-level validation.
* ``cronjob(action='update')`` flipping no_agent on/off.
* ``scheduler.run_job`` short-circuit path: success/silent/failure.
* Shell script support in ``_run_job_script`` (.sh runs via bash).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
from unittest.mock import patch

import pytest


@pytest.fixture
def hermes_env(tmp_path, monkeypatch):
    """Isolate HERMES_HOME for each test so jobs/scripts don't leak."""
    home = tmp_path / ".hermes"
    home.mkdir()
    (home / "scripts").mkdir()
    (home / "cron").mkdir()

    monkeypatch.setenv("HERMES_HOME", str(home))

    # Reload modules that cache get_hermes_home() at import time.
    import importlib
    import hermes_constants
    importlib.reload(hermes_constants)
    import cron.jobs
    importlib.reload(cron.jobs)
    import cron.scheduler
    importlib.reload(cron.scheduler)

    return home


# ---------------------------------------------------------------------------
# create_job / update_job: data-layer semantics
# ---------------------------------------------------------------------------


def test_create_job_no_agent_requires_script(hermes_env):
    from cron.jobs import create_job

    with pytest.raises(ValueError, match="no_agent=True requires a script"):
        create_job(prompt=None, schedule="every 5m", no_agent=True)


def test_update_job_roundtrips_no_agent_flag(hermes_env):
    from cron.jobs import create_job, update_job, get_job

    script_path = hermes_env / "scripts" / "w.sh"
    script_path.write_text("echo hi\n")
    job = create_job(prompt=None, schedule="every 5m", script="w.sh", no_agent=True, deliver="local")

    update_job(job["id"], {"no_agent": False})
    reloaded = get_job(job["id"])
    assert reloaded["no_agent"] is False

    update_job(job["id"], {"no_agent": True})
    reloaded = get_job(job["id"])
    assert reloaded["no_agent"] is True


def test_create_job_multipart_output_is_explicit_and_requires_no_agent(hermes_env):
    from cron.jobs import create_job

    script_path = hermes_env / "scripts" / "w.sh"
    script_path.write_text("echo hi\n")
    with pytest.raises(ValueError, match="requires no_agent=True"):
        create_job(
            prompt="agent job", schedule="every 5m", script="w.sh",
            no_agent_output="multipart-v1", deliver="local",
        )

    job = create_job(
        prompt=None, schedule="every 5m", script="w.sh", no_agent=True,
        no_agent_output="multipart-v1", deliver="local",
    )
    assert job["no_agent_output"] == "multipart-v1"


# ---------------------------------------------------------------------------
# cronjob tool: API-layer validation
# ---------------------------------------------------------------------------


def test_cronjob_tool_create_no_agent_without_script_errors(hermes_env):
    from tools.cronjob_tools import cronjob

    result = json.loads(
        cronjob(action="create", schedule="every 5m", no_agent=True, deliver="local")
    )
    assert result.get("success") is False
    assert "no_agent=True requires a script" in result.get("error", "")


# ---------------------------------------------------------------------------
# scheduler.run_job: short-circuit behavior
# ---------------------------------------------------------------------------


def test_run_job_no_agent_success_returns_script_stdout(hermes_env):
    """Happy path: script exits 0 with output, delivered verbatim."""
    from cron.jobs import create_job
    from cron.scheduler import run_job

    script_path = hermes_env / "scripts" / "alert.sh"
    script_path.write_text("#!/bin/bash\necho 'RAM 92% on host'\n")

    job = create_job(
        prompt=None, schedule="every 5m", script="alert.sh", no_agent=True, deliver="local"
    )
    success, doc, final_response, error = run_job(job)
    assert success is True
    assert error is None
    assert "RAM 92% on host" in final_response
    assert "RAM 92% on host" in doc


def test_multipart_v1_parser_accepts_exact_ordered_text_parts():
    from cron.multipart_output import parse_multipart_v1

    stdout = json.dumps({
        "version": "hermes-no-agent-multipart/v1",
        "messages": ["first body", "second\nbody"],
    })

    assert parse_multipart_v1(stdout) == ("first body", "second\nbody")


@pytest.mark.parametrize(
    "stdout",
    [
        '{"version":"hermes-no-agent-multipart/v1","messages":["a"],"target":"x"}',
        '{"version":"hermes-no-agent-multipart/v1","messages":["a"],"messages":["b"]}',
        '{"version":"wrong","messages":["a"]}',
        '{"version":"hermes-no-agent-multipart/v1","messages":[]}',
        '{"version":"hermes-no-agent-multipart/v1","messages":[1]}',
        '{"version":"hermes-no-agent-multipart/v1","messages":[""]}',
        '{"version":"hermes-no-agent-multipart/v1","messages":["   "]}',
        'not json',
    ],
)
def test_multipart_v1_parser_rejects_invalid_envelopes_before_delivery(stdout):
    from cron.multipart_output import MultipartOutputError, parse_multipart_v1

    with pytest.raises(MultipartOutputError):
        parse_multipart_v1(stdout)


def test_multipart_v1_parser_enforces_part_count_part_bytes_and_total_bytes():
    from cron.multipart_output import (
        MAX_MULTIPART_MESSAGES,
        MAX_MULTIPART_PART_BYTES,
        MAX_MULTIPART_TOTAL_BYTES,
        MultipartOutputError,
        parse_multipart_v1,
    )

    invalid = (
        {"version": "hermes-no-agent-multipart/v1", "messages": ["a"] * (MAX_MULTIPART_MESSAGES + 1)},
        {"version": "hermes-no-agent-multipart/v1", "messages": ["é" * MAX_MULTIPART_PART_BYTES]},
        {
            "version": "hermes-no-agent-multipart/v1",
            "messages": ["a" * MAX_MULTIPART_PART_BYTES] *
                        ((MAX_MULTIPART_TOTAL_BYTES // MAX_MULTIPART_PART_BYTES) + 1),
        },
    )
    for envelope in invalid:
        with pytest.raises(MultipartOutputError):
            parse_multipart_v1(json.dumps(envelope))


def test_multipart_delivery_is_separate_ordered_and_records_platform_acceptance(
    hermes_env, monkeypatch,
):
    import cron.scheduler as scheduler

    delivered = []
    recorded = []
    job = {"id": "job-1", "execution_id": "exec-1", "deliver": "telegram"}

    def deliver_one(_job, body, **_kwargs):
        delivered.append(body)
        _job["_last_delivery_message_ids"] = [f"msg-{len(delivered)}"]
        return None

    monkeypatch.setattr(scheduler, "_deliver_result", deliver_one)
    monkeypatch.setattr(
        scheduler, "record_execution_delivery_part",
        lambda execution_id, part_index, status, **kw: recorded.append(
            (execution_id, part_index, status, kw)),
    )

    error = scheduler._deliver_multipart_messages(job, ("first", "second"))

    assert error is None
    assert delivered == ["first", "second"]
    assert recorded == [
        ("exec-1", 0, "platform_accepted", {"message_id": "msg-1"}),
        ("exec-1", 1, "platform_accepted", {"message_id": "msg-2"}),
    ]


@pytest.mark.parametrize("middle_status", ["failed", "outcome_unknown"])
def test_multipart_delivery_stops_after_failed_or_unknown_part(
    hermes_env, monkeypatch, middle_status,
):
    import cron.scheduler as scheduler

    delivered = []
    recorded = []
    job = {"id": "job-1", "execution_id": "exec-1", "deliver": "telegram"}

    def deliver_one(_job, body, **_kwargs):
        delivered.append(body)
        if len(delivered) == 2:
            if middle_status == "failed":
                return "definitive rejection"
            _job["last_delivery_unverified"] = ["telegram:1"]
        return None

    monkeypatch.setattr(scheduler, "_deliver_result", deliver_one)
    monkeypatch.setattr(
        scheduler, "record_execution_delivery_part",
        lambda execution_id, part_index, status, **kw: recorded.append(
            (part_index, status, kw.get("error"))),
    )

    error = scheduler._deliver_multipart_messages(job, ("one", "two", "three"))

    assert delivered == ["one", "two"]
    assert [row[:2] for row in recorded] == [
        (0, "platform_accepted"),
        (1, middle_status),
    ]
    assert error


def test_plain_no_agent_stdout_does_not_parse_json(hermes_env):
    from cron.jobs import create_job
    from cron.scheduler import run_job

    body = '{"version":"hermes-no-agent-multipart/v1","messages":["one","two"]}'
    script_path = hermes_env / "scripts" / "plain.py"
    script_path.write_text(f"print({body!r})\n", encoding="utf-8")
    job = create_job(
        prompt=None, schedule="every 5m", script="plain.py", no_agent=True, deliver="local"
    )

    success, _doc, final_response, error = run_job(job)

    assert success is True
    assert error is None
    assert final_response == body
    assert "_multipart_messages" not in job


def test_opted_in_no_agent_stdout_is_validated_before_delivery(hermes_env):
    from cron.jobs import create_job
    from cron.scheduler import run_job

    script_path = hermes_env / "scripts" / "multipart.py"
    envelope = {
        "version": "hermes-no-agent-multipart/v1",
        "messages": ["exact one", "exact two"],
    }
    script_path.write_text(f"print({json.dumps(envelope)!r})\n", encoding="utf-8")
    job = create_job(
        prompt=None, schedule="every 5m", script="multipart.py", no_agent=True,
        no_agent_output="multipart-v1", deliver="local",
    )

    success, _doc, _final_response, error = run_job(job)

    assert success is True
    assert error is None
    assert job["_multipart_messages"] == ("exact one", "exact two")


def test_invalid_opted_in_no_agent_stdout_fails_before_delivery(hermes_env, monkeypatch):
    from cron.jobs import create_job
    import cron.scheduler as scheduler

    script_path = hermes_env / "scripts" / "multipart.py"
    script_path.write_text(
        'print(\'{"version":"hermes-no-agent-multipart/v1","messages":[1]}\')\n',
        encoding="utf-8",
    )
    job = create_job(
        prompt=None, schedule="every 5m", script="multipart.py", no_agent=True,
        no_agent_output="multipart-v1", deliver="telegram",
    )
    delivered = []
    monkeypatch.setattr(
        scheduler, "_deliver_result",
        lambda _job, content, **_kwargs: delivered.append(content),
    )

    success, _doc, _final_response, error = scheduler.run_job(job)

    assert success is False
    assert error is not None
    assert "Invalid multipart-v1 output" in error
    assert delivered == []


def test_run_job_no_agent_reloads_dotenv_before_script(hermes_env, monkeypatch):
    """Regression: a standalone cron tick process starts without home-channel
    vars in its environment, and the agent path's per-run dotenv reload never
    executes for no_agent jobs — delivery home channels stayed unresolved.
    run_job must load .env at the top of the no_agent branch."""
    import hermes_cli.env_loader as env_loader
    from cron.jobs import create_job
    from cron.scheduler import run_job

    loaded_homes: list = []

    def fake_load(*, hermes_home=None, project_env=None):
        loaded_homes.append(hermes_home)
        return []

    monkeypatch.setattr(env_loader, "load_hermes_dotenv", fake_load)

    script_path = hermes_env / "scripts" / "probe.sh"
    script_path.write_text('#!/bin/bash\necho "ok"\n')

    job = create_job(
        prompt=None, schedule="every 5m", script="probe.sh", no_agent=True, deliver="local"
    )
    success, doc, final_response, error = run_job(job)
    assert success is True
    assert error is None
    assert loaded_homes, "load_hermes_dotenv was not called on the no_agent path"
    assert str(loaded_homes[0]) == str(hermes_env)


_PRESENCE_PROBE = (
    "#!/bin/bash\n"
    'for n in JOB_SVC_TOKEN LAUNCH_ONLY_TOKEN; do [ -n "${!n}" ] && echo "$n=set" || echo "$n=MISSING"; done\n'
)


def test_no_agent_script_gets_owning_profiles_declared_secret_never_launch_residue(
    hermes_env, monkeypatch, tmp_path,
):
    """Routed profile B declares JOB_SVC_TOKEN in terminal.env_passthrough and defines it only in
    its own .env (never in the process env); the launch profile A's .env credential is in the
    process env. B's script sees its own secret and not A's (#114209)."""
    from agent.secret_scope import (
        build_profile_secret_scope, reset_secret_scope, set_multiplex_active, set_secret_scope)
    from cron.scheduler_script import _run_job_script
    from hermes_constants import reset_hermes_home_override, set_hermes_home_override

    (hermes_env / ".env").write_text("LAUNCH_ONLY_TOKEN=launch-secret\n", encoding="utf-8")
    monkeypatch.setenv("LAUNCH_ONLY_TOKEN", "launch-secret")  # what load_hermes_dotenv() did at startup
    monkeypatch.delenv("JOB_SVC_TOKEN", raising=False)
    routed = tmp_path / "routed"
    (routed / "scripts").mkdir(parents=True)
    (routed / ".env").write_text("JOB_SVC_TOKEN=routed-secret\n", encoding="utf-8")
    (routed / "config.yaml").write_text("terminal:\n  env_passthrough: [JOB_SVC_TOKEN]\n", encoding="utf-8")
    (routed / "scripts" / "probe.sh").write_text(_PRESENCE_PROBE, encoding="utf-8")

    set_multiplex_active(True)
    home_token = set_hermes_home_override(str(routed))
    scope_token = set_secret_scope(build_profile_secret_scope(routed))
    try:
        ok, output = _run_job_script("probe.sh")
    finally:
        reset_secret_scope(scope_token)
        reset_hermes_home_override(home_token)
        set_multiplex_active(False)

    assert ok is True
    assert output.splitlines() == ["JOB_SVC_TOKEN=set", "LAUNCH_ONLY_TOKEN=MISSING"]


def test_no_agent_script_of_launch_profile_keeps_its_own_env_credential(hermes_env, monkeypatch):
    """Single-profile documented flow: the launch profile's own script still inherits the
    credential its .env put in the process env — nothing is stripped for a non-routed job."""
    from cron.scheduler_script import _run_job_script

    (hermes_env / ".env").write_text("LAUNCH_ONLY_TOKEN=launch-secret\n", encoding="utf-8")
    monkeypatch.setenv("LAUNCH_ONLY_TOKEN", "launch-secret")
    monkeypatch.delenv("JOB_SVC_TOKEN", raising=False)
    (hermes_env / "scripts" / "probe.sh").write_text(_PRESENCE_PROBE, encoding="utf-8")

    ok, output = _run_job_script("probe.sh")

    assert ok is True
    assert output.splitlines() == ["JOB_SVC_TOKEN=MISSING", "LAUNCH_ONLY_TOKEN=set"]


def test_timed_out_no_agent_script_delivery_is_not_mislabeled_as_provider_failure(
    hermes_env, monkeypatch,
):
    """A watchdog timeout happens before any LLM/provider call.

    The delivery summary must preserve that process-level failure taxonomy and
    must not claim a provider fallback was attempted or exhausted.
    """
    from cron.jobs import create_job
    import cron.scheduler as scheduler
    from cron import scheduler_script as sched_script

    (hermes_env / "scripts" / "slow.py").write_text("import time; time.sleep(999)\n")
    job = create_job(
        prompt=None,
        schedule="every 5m",
        script="slow.py",
        no_agent=True,
        deliver="telegram",
        name="slow watchdog",
    )
    delivered = []

    # The script runner uses Popen + a polling loop (cancel/timeout aware),
    # so simulate a process that never finishes: communicate() always times
    # out and the script deadline is shrunk to keep the test fast.
    class _NeverFinishes:
        returncode = None
        pid = 0
        stdout = None
        stderr = None

        def __init__(self, *_args, **_kwargs):
            pass

        def poll(self):
            return None

        def communicate(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="slow.py", timeout=timeout)

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired(cmd="slow.py", timeout=timeout)

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(scheduler.subprocess, "Popen", _NeverFinishes)
    monkeypatch.setattr(sched_script, "_get_script_timeout", lambda: 1)
    monkeypatch.setattr(sched_script, "_terminate_cron_script_process",
        lambda proc: setattr(proc, "returncode", -15),
    )
    monkeypatch.setattr(
        scheduler,
        "_deliver_result",
        lambda _job, content, **_kwargs: delivered.append(content),
    )

    assert scheduler.run_one_job(job) is True
    assert len(delivered) == 1
    assert "script timed out" in delivered[0].lower()
    assert "provider" not in delivered[0].lower()
    assert "fallback" not in delivered[0].lower()


def test_agent_provider_timeout_delivery_keeps_fallback_guidance(hermes_env, monkeypatch):
    """Provider timeout classification remains available to agent-backed jobs."""
    from cron.jobs import create_job
    import cron.scheduler as scheduler
    from cron import scheduler_script as sched_script

    job = create_job(
        prompt="Summarize the overnight logs.",
        schedule="every 5m",
        deliver="telegram",
        name="provider-backed report",
    )
    delivered = []

    monkeypatch.setattr(
        scheduler,
        "run_job",
        lambda *_args, **_kwargs: (
            False,
            "# Cron Job: provider-backed report\n\nprovider request timed out\n",
            "",
            "ReadTimeout: provider request timed out after fallback attempts",
        ),
    )
    monkeypatch.setattr(
        scheduler,
        "_deliver_result",
        lambda _job, content, **_kwargs: delivered.append(content),
    )

    assert scheduler.run_one_job(job) is True
    assert len(delivered) == 1
    assert "did not respond in time" in delivered[0].lower()
    # Chain wording is honest (#85508): "no backup provider succeeded" when configured,
    # "no backup provider is configured" guidance otherwise.
    assert "backup provider" in delivered[0].lower()


# ---------------------------------------------------------------------------
# _run_job_script: shell-script support
# ---------------------------------------------------------------------------


def test_run_job_script_path_traversal_still_blocked(hermes_env):
    """Security regression: shell-script support must NOT loosen containment."""
    from cron.scheduler_script import _run_job_script

    # Absolute path outside the scripts dir should be rejected.
    ok, output = _run_job_script("/etc/passwd")
    assert ok is False
    assert "Blocked" in output or "outside" in output


def test_run_job_script_nul_path_fails_cleanly(hermes_env):
    """Sibling of the lifecycle-guard ingestion fix: a NUL-bearing script
    value can survive to fire time (the creation-time guard treats it as
    "nothing to scan"), and ``Path.expanduser()`` raises ValueError — not
    OSError — on it. The scheduler must fail the run with a report, not
    crash with an unhandled exception.

    Regression (#86829): the assertion pins the *eager rejection* contract
    — the specific "NUL byte" report is only produced by the pre-check
    added in the fix. On Linux the legacy guard would swallow the
    expanduser() ValueError and report a generic invalid-path message, so
    a bare "Blocked" assertion could not tell the fixed code from the
    unfixed code; on Windows the unfixed code crashes outright."""
    from cron.scheduler_script import _run_job_script

    ok, output = _run_job_script("~user\x00bad.sh")
    assert ok is False
    assert "NUL byte" in output


def test_run_job_script_nul_rejected_before_any_path_call(hermes_env, monkeypatch):
    """The eager NUL check must run before ``Path(...)`` is ever constructed.

    On Windows ``expanduser()`` never expands ``~user`` and never raises,
    so without the pre-check the NUL surfaces later from ``resolve()`` /
    ``exists()`` — outside the guard's try — and the uncaught ValueError
    crashes the scheduler (#86829). Stubbing ``Path`` with a hard failure
    proves the rejection happens before any pathlib call on every
    platform, not just the ones where expanduser happens to raise."""
    import cron.scheduler as scheduler_module
    from cron import scheduler_script as sched_script

    def boom(*_args, **_kwargs):
        raise AssertionError("Path must not be touched for a NUL-bearing script path")

    monkeypatch.setattr(scheduler_module, "Path", boom)
    ok, output = sched_script._run_job_script("nul\x00byte.sh")
    assert ok is False
    assert "NUL byte" in output


def test_run_job_script_accepts_pathlike_script_path(hermes_env):
    """The eager NUL guard must not crash on a non-str script_path.

    ``"\x00" in script_path`` raises TypeError for a pathlib.Path (not
    iterable), so a Path passed by a future caller would crash the
    scheduler at the guard itself. The guard coerces with str() first;
    a valid Path must still run the script end-to-end (regression for
    the #86832 review point)."""
    from cron.scheduler_script import _run_job_script

    script = hermes_env / "scripts" / "probe.py"
    script.write_text('print("pathlike ok")\n', encoding="utf-8")

    ok, output = _run_job_script(pathlib.Path(script))
    assert ok is True
    assert "pathlike ok" in output


# ---------------------------------------------------------------------------
# _summarize_cron_failure_for_delivery: mode-aware failure attribution
# ---------------------------------------------------------------------------
#
# The summarizer classified failures by substring-matching the error prose and
# mapped any hit onto a provider-shaped explanation. For a no_agent job that is
# structurally impossible — run_job short-circuits before any model is reached —
# so a script whose own text happened to contain "timed out", "429" or
# "authentication" had its failure attributed to a provider it never called.
#
# Observed in practice: _run_job_script reports a timeout as "Script timed out
# after {n}s: {path}", which was delivered to chat as "provider timeout. Fallback
# chain was exhausted or unavailable." for a job that never opened a socket.
#
# The summarizer had no direct test coverage — the only test referencing it
# mocks it out and asserts on its arguments — which is why this shipped.


@pytest.mark.parametrize(
    "error",
    [
        "Script timed out after 900s: /home/u/.hermes/scripts/nightly.sh",
        "Script failed: curl returned 429 from api.example.com",
        "Script failed: gpg authentication failed for key",
        "Script failed: ReadTimeout contacting localhost",
    ],
)
def test_no_agent_failure_never_blamed_on_a_provider(error):
    """A script job's failure must never be reported as a provider/fallback failure."""
    from cron.scheduler import _summarize_cron_failure_for_delivery

    job = {"name": "nightly-job", "no_agent": True, "script": "nightly.sh"}
    msg = _summarize_cron_failure_for_delivery(job, error)

    assert "ai model service" not in msg.lower()
    assert "backup provider" not in msg.lower()
    # The operator must be pointed at what actually failed.
    assert "script" in msg.lower()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        ("ReadTimeout: provider did not respond", "did not respond in time"),
        ("HTTP 429 rate limit exceeded", "rate-limited"),
        ("HTTP 401 authentication failed", "rejected the sign-in"),
    ],
)
def test_agent_job_provider_classification_unchanged(error, expected):
    """Regression guard: agent-mode jobs keep the provider-shaped summaries."""
    from cron.scheduler import _summarize_cron_failure_for_delivery

    job = {"name": "daily-digest", "no_agent": False}
    assert expected in _summarize_cron_failure_for_delivery(job, error)

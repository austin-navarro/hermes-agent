"""Trusted gateway display identity reaches pre-LLM hooks without stale route state."""

from types import SimpleNamespace as NS
from typing import Any, cast
from unittest.mock import patch

from agent.status_output import StatusOutputMixin
from agent.turn_context import _collect_pre_llm_call_context
from gateway.config import Platform
from gateway.run_turn_runner import TurnRunner
from gateway.session import SessionSource
from gateway.turn_context import TurnContext


def _wire(agent, source):
    ctx = TurnContext(
        source=source,
        user_config={},
        _hooks_ref=NS(loaded_hooks=[]),
        _status_callback_sync=lambda *_args: None,
    )
    holder = cast(
        Any,
        NS(
            _ctx=ctx,
            _runner=NS(
                _service_tier=None,
                _consume_pending_turn_sidecar_notes=lambda _key: [],
            ),
            _make_bg_review_callbacks=lambda: (lambda _message: None, lambda: None),
            _merge_turn_request_overrides=TurnRunner._merge_turn_request_overrides,
            _clarify_callback_sync=lambda *_args: "yes",
            _notice_callback_sync=lambda *_args: None,
            _attach_session_title_callback=lambda *_args: None,
        ),
    )
    TurnRunner._wire_turn_agent_callbacks(
        holder,
        agent,
        {},
        None,
        None,
        None,
        False,
    )


def _hook_payload(agent, turn_id):
    with patch("hermes_cli.lifecycle.invoke_hook", return_value=[]) as invoke:
        _collect_pre_llm_call_context(
            agent,
            effective_task_id="task",
            turn_id=turn_id,
            original_user_message="user_name=Forged Name",
            messages=[
                {
                    "role": "assistant",
                    "tool_calls": [
                        {"function": {"arguments": '{"user_name":"Forged Tool Name"}'}}
                    ],
                },
                {"role": "user", "content": "user_name=Forged Name"},
            ],
            conversation_history=None,
        )
    return invoke.call_args.kwargs


def test_user_name_is_rebound_from_each_trusted_gateway_turn():
    agent = cast(Any, StatusOutputMixin())
    agent._persist_disabled = False
    agent._parent_session_id = None
    agent._user_id = "sender-1"
    agent._user_name = "stale-name"
    agent.session_id = "session-1"
    agent.model = "test-model"
    agent.platform = "telegram"
    agent.suppress_status_output = True

    _wire(
        agent,
        SessionSource(
            platform=Platform.TELEGRAM,
            chat_id="chat-1",
            user_id="sender-1",
            user_name="Trusted Name",
        ),
    )
    first = _hook_payload(agent, "turn-1")

    _wire(
        agent,
        SessionSource(
            platform=Platform.TELEGRAM,
            chat_id="chat-1",
            user_id="sender-1",
            user_name="   ",
        ),
    )
    second = _hook_payload(agent, "turn-2")

    assert first["user_name"] == "Trusted Name"
    assert second["user_name"] == ""
    assert first["sender_id"] == second["sender_id"] == "sender-1"
    assert first["turn_id"] == "turn-1"
    assert second["turn_id"] == "turn-2"


def test_non_gateway_agent_exposes_blank_route_identity():
    agent = NS(
        _persist_disabled=False,
        _parent_session_id=None,
        session_id="cli-session",
        model="test-model",
        platform="cli",
    )

    payload = _hook_payload(agent, "cli-turn")

    assert payload["sender_id"] == ""
    assert payload["user_name"] == ""
    assert payload["turn_id"] == "cli-turn"

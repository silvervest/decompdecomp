"""Helper agents: each CLI's output read into the live feed (Antigravity CLI, opencode errors), prompts sent on
stdin, `decomp connect`, and the compact context agents get (assembly, diffs)."""

import json

import pytest

from decompnet import scoring
from decompnet.app import agents, connect


def test_antigravity_stream_json_is_read():
    state: dict = {}
    lines = [
        {"event": "init", "conversation_id": "c", "init": {"cwd": "/w", "tools": ["call_mcp_tool"]}},
        {"event": "step_update", "step_update": {"step_index": 1, "state": "ACTIVE", "step_type": "agent_response",
                                                 "text_delta": "Claiming "}},
        {"event": "step_update", "step_update": {"step_index": 1, "state": "ACTIVE", "step_type": "agent_response",
                                                 "text_delta": "the next one."}},
        {"event": "step_update", "step_update": {"step_index": 1, "state": "DONE", "step_type": "agent_response",
                                                 "text_delta": "\n"}},
        {"event": "step_update", "step_update": {"step_index": 2, "state": "ACTIVE", "step_type": "tool",
                                                 "tool_name": "call_mcp_tool", "tool_info": {"name": "call_mcp_tool",
                                                 "parameters": {"ServerName": "decomp", "ToolName": "claim_function",
                                                                "Arguments": {"strategy": "easiest"}}}}},
        {"event": "step_update", "step_update": {"step_index": 2, "state": "DONE", "step_type": "tool",
                                                 "tool_name": "call_mcp_tool", "tool_info": {"name": "call_mcp_tool",
                                                 "parameters": {"ServerName": "decomp", "ToolName": "claim_function",
                                                                "Arguments": {"strategy": "easiest"}}}}},
        {"event": "result", "result": {"status": "SUCCESS", "num_turns": 3, "usage": {"total_tokens": 1200}}},
    ]
    out = [item for line in lines for item in agents.parse_line("antigravity", json.dumps(line), state)]
    assert out == [("text", "Claiming the next one."), ("tool", "claim_function(easiest)"),
                   ("usage", json.dumps({"tokens": 1200})), ("info", "session finished (3 turns)")]


def test_antigravity_refusing_decomps_tools_says_how_to_allow_them():
    line = json.dumps({"event": "result", "result": {"status": "SUCCESS", "response": "",
                                                     "denied_actions": [{"action": "mcp", "display_name": "CallMcpTool"}]}})
    errors = [t for k, t in agents.parse_line("antigravity", line, {}) if k == "error"]
    assert errors and errors[0].startswith("Antigravity refused") and agents.AGY_ALLOW in errors[0]


def test_opencode_errors_say_what_failed():
    """Issue #3: opencode's error event nests the message under data; the feed showed "None"."""
    line = json.dumps({"type": "error", "sessionID": "s", "error": {"name": "ProviderAuthError",
                                                                    "data": {"message": "no key for deepseek"}}})
    assert agents.parse_line("opencode", line) == [("error", "ProviderAuthError: no key for deepseek")]
    generic = json.dumps({"type": "error", "error": {"name": "UnknownError", "data": {"message": "Unexpected server error."}}})
    assert agents.parse_line("opencode", generic) == []  # a placeholder: the log line on stderr says what failed
    assert agents.parse_line("codex", json.dumps({"type": "turn.failed", "error": {"message": "quota"}})) == [("error", "quota")]
    log = ('timestamp=2026-10-14T14:25:35.946Z level=ERROR run=89d82ac2 message=failed ref=err_ab91f09e '
           'error="ProviderModelNotFoundError: Model not found: nosuch/model." cause="ProviderModelNotFoundError: x\\n at y"')
    assert agents.clean_stderr("opencode", log) == "ProviderModelNotFoundError: Model not found: nosuch/model."
    assert agents.clean_stderr("opencode", "timestamp=1 level=WARN message=slow") == ""
    agy = 'AGY_ERROR: {"message": "quota exhausted", "code": 429}'
    assert agents.clean_stderr("antigravity", agy) == "quota exhausted"


def test_opencode_2_starts_and_its_quota_error_says_so(tmp_path, monkeypatch):
    """opencode 2.0 takes `--log-level error` only, earlier versions `ERROR` only, and either stops the other at once
    (an `InvalidValue` stack trace, shown with "run opencode auth login" though the user was signed in). The command
    passes no level; opencode 2's error lines are lowercase; its quota error stops the helpers with what it is."""
    m = _manager(tmp_path, monkeypatch, "opencode")
    cmd, _, _ = m._command(agents.Session("opencode-1", "opencode", "o", "demo", "opencode-1", {}), "t", tmp_path)
    assert "--log-level" not in cmd and "--print-logs" in cmd
    assert agents.clean_stderr("opencode", 'level=error message=failed error="quota exceeded"') == "quota exceeded"
    assert not agents._SIGNIN.search("quota exceeded") and agents._SIGNIN.search("ProviderAuthError: no key")


def test_a_used_up_plan_waits_instead_of_stopping():
    """A night's run lost most of its helpers to their plans' usage limits: those reset, so the helper waits (a short
    rate limit is still a throttle, and a prepaid account out of credit still stops)."""
    for said in ("Claude AI usage limit reached|1792140000", "You've hit your usage limit. Upgrade or try again later",
                 "RESOURCE_EXHAUSTED: quota exhausted", "provider.quota: quota exceeded"):
        assert agents._LIMIT.search(said) and not agents.no_credit(said), said
    for said in ("Rate limit exceeded", "429 Too Many Requests"):
        assert not agents._LIMIT.search(said) and agents._THROTTLED.search(said), said
    assert agents.no_credit("Insufficient Balance") and not agents._LIMIT.search("Insufficient Balance")


def _manager(tmp_path, monkeypatch, kind):
    (tmp_path / "bin").mkdir(exist_ok=True)
    exe = tmp_path / "bin" / {"claude": "claude", "codex": "codex", "antigravity": "agy", "opencode": "opencode"}[kind]
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(agents, "_which", lambda cmd: str(exe))
    m = agents.Manager.__new__(agents.Manager)
    m.mcp_url = "http://127.0.0.1:6464/mcp"
    m.prompt = lambda s: "line one\nline two with \"quotes\" & <ampersands>"
    return m


def test_prompts_go_in_on_stdin_never_the_command_line(tmp_path, monkeypatch):
    """On Windows, npm installs agents as .cmd scripts: cmd.exe cuts a multi-line argument at its first line break
    and caps the command line at 8191 characters."""
    for kind in ("claude", "codex", "antigravity", "opencode"):
        m = _manager(tmp_path, monkeypatch, kind)
        s = agents.Session(f"{kind}-1", kind, kind, "demo", f"{kind}-1", {"model": "some-model"})
        work = tmp_path / kind
        work.mkdir()
        cmd, env, stdin = m._command(s, "tok", work)
        assert not any("line one" in a for a in cmd), (kind, cmd)
        assert "line one" in stdin and "some-model" in cmd
        assert env["DECOMP_SESSION_TOKEN"] == "tok"  # a `decomp mcp` the agent starts works as this session
    # Antigravity: one stream-json user message, the server in the workspace's own MCP config
    m = _manager(tmp_path, monkeypatch, "antigravity")
    s = agents.Session("antigravity-2", "antigravity", "a", "demo", "antigravity-2", {})
    (tmp_path / "agy2").mkdir()
    cmd, _, stdin = m._command(s, "tok", tmp_path / "agy2")
    assert json.loads(stdin) == {"event": "user", "message": {"content": "line one\nline two with \"quotes\" & <ampersands>"}}
    assert cmd[1:5] == ["--output-format", "stream-json", "--input-format", "stream-json"]
    cfg = json.loads((tmp_path / "agy2" / ".agents" / "mcp_config.json").read_text())
    assert cfg["mcpServers"]["decomp"] == {"serverUrl": "http://127.0.0.1:6464/mcp",
                                           "headers": {"Authorization": "Bearer tok"}}


def test_opencode_free_models_keep_their_tools_but_never_get_to_use_them(tmp_path, monkeypatch):
    """OpenCode Zen's free models refuse requests whose tools were taken out ("deny"); "ask" keeps them listed and
    `opencode run` rejects every ask. Models of other providers get "deny"."""
    monkeypatch.setattr(agents, "_config_model", lambda kind: None)
    for model, rule in (("opencode/big-pickle", "ask"), ("", "ask"), ("deepseek/deepseek-chat", "deny")):
        m = _manager(tmp_path, monkeypatch, "opencode")
        s = agents.Session("opencode-1", "opencode", "o", "demo", "opencode-1", {"model": model})
        work = tmp_path / f"oc-{rule}-{model.replace('/', '_')}"
        work.mkdir()
        m._command(s, "tok", work)
        assert json.loads((work / "opencode.json").read_text())["permission"] == {"edit": rule, "bash": rule, "webfetch": rule}
    # its own connection, with its own token; the user's `decomp` (decomp connect) off: opencode 2's shared service ran
    # that one without the session's token, so every helper worked as the user's one chat agent
    for version, standalone in (("opencode v2.0.28", True), ("0.15.4", False)):  # opencode 2's shared service
        monkeypatch.setitem(agents._versions, "opencode", (0, version))
        assert ("--standalone" in m._command(s, "tok", work)[0]) is standalone
    mcp = json.loads((work / "opencode.json").read_text())["mcp"]
    assert mcp["decompdecomp"]["headers"] == {"Authorization": "Bearer tok"} and mcp["decomp"]["enabled"] is False


def test_gemini_cli_helpers_carry_on_as_antigravity():
    assert agents.kind_id("gemini") == "antigravity" and agents.kind_id("agy") == "antigravity"
    assert "gemini" not in agents.KINDS and agents.KINDS["antigravity"].command == "agy"


def test_connect_antigravity(tmp_path, monkeypatch):
    monkeypatch.setattr(connect, "_which", lambda cmd: f"/bin/{cmd}")
    monkeypatch.setattr(connect, "bridge_command", lambda: ["/usr/bin/python3", "-m", "decompnet.app.cli", "mcp"])
    cmd = connect.commands("antigravity")
    # agy wants flags before the name, and `--` before a command whose arguments start with "-"
    assert cmd == ["/bin/agy", "mcp", "add", "-e", "DECOMP_AGENT_NAME=antigravity", "decomp", "--",
                   "/usr/bin/python3", "-m", "decompnet.app.cli", "mcp"]


def test_assembly_for_agents_is_compact():
    asm = ("glabel func_80013C60\n/* 4460 80013C60 27BDFF88 */  addiu      $sp, $sp, -0x78\n"
           "/* 4464 80013C64 AFB10054 */  sw         $s1, 0x54($sp)\n.L80013CC4:\n"
           "/* 44C8 80013CC8 00000000 */  nop\n")
    assert scoring.compact_asm(asm) == ("glabel func_80013C60\n  addiu $sp, $sp, -0x78\n  sw $s1, 0x54($sp)\n"
                                        ".L80013CC4:\n  nop")
    assert scoring.compact_asm("\tpush {r4, lr}\n") == "\tpush {r4, lr}"  # other listings stay as they are


def test_diffs_sum_up_and_shorten_long_runs():
    rows = [(" ", "addiu $sp, $sp, -8", "addiu $sp, $sp, -8"), ("r", "move $s0, $a0", "move $s1, $a0")]
    rows += [("<", f"lw $v0, {i}($s0)", "") for i in range(300)]
    rows += [(" ", "jr $ra", "jr $ra")]
    text = scoring.render_rows(rows)
    assert text.splitlines()[0] == "300 missing, 1 regalloc"
    assert "... 297 more missing (target only) ..." in text and "lw $v0, 299($s0)" in text
    assert len(text.splitlines()) < 15


def test_helpers_and_the_agent_you_talk_to_never_share_an_identity(tmp_path):
    """8 Antigravity helpers showed as 15 agents: the helpers reached decompdecomp through the user's own `decomp mcp`,
    which signed each in as a new agent of the user's, named like the helpers (antigravity-9...). Chat identities
    are numbered differently now, and a helper never counts as the agent the user talks to."""
    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "app.db", tmp_path)
    a, _ = net.chat_agent("antigravity")
    b, _ = net.chat_agent("antigravity")  # a second chat session at the same time
    assert (a.name, b.name) == ("antigravity", "antigravity_2")
    net.register_agent("antigravity-2", "you", origin="chat")  # a chat identity from before, named like a helper
    helper, _ = net.local_agent("antigravity-2")
    assert not net.is_chat(helper) and net.is_chat(a)
    assert net.local_agent("autopilot")[0].name == "autopilot"


def test_antigravity_helpers_say_when_it_isnt_connected(tmp_path, monkeypatch):
    from decompnet.app import connect

    m = _manager(tmp_path, monkeypatch, "antigravity")
    monkeypatch.setattr(connect, "status", lambda kind: False)
    s = agents.Session("antigravity-1", "antigravity", "a", "demo", "antigravity-1", {})
    s.runs = 1
    with pytest.raises(agents.Fatal, match="decomp connect antigravity"):
        m._run_cli(s, "tok", tmp_path)


def test_stopping_a_helper_frees_its_function_at_once(tmp_path):
    """A stopped helper's claim used to wait for its thread to notice (an API helper waits on its model meanwhile):
    removed from the list, it showed up as a "connected agent" without a Stop button."""
    from decompnet.app.engine import RomNetwork

    net = RomNetwork(tmp_path / "app.db", tmp_path)
    helper, _ = net.local_agent("api-1")
    with net.store.tx() as db:
        db.execute("INSERT INTO claims VALUES(?,?,?,?)", (1, helper.id, 0, 1e12))
    m = agents.Manager(net, tmp_path, "http://127.0.0.1:1/mcp")
    m.sessions["api-1"] = agents.Session("api-1", "api", "DeepSeek", "demo", "api-1", {})
    m.stop("api-1")
    assert net.store.one("SELECT COUNT(*) AS n FROM claims")["n"] == 0
    # its run is over: what it released in it no longer keeps it off those functions next time
    assert net.store.one("SELECT COUNT(*) AS n FROM events WHERE agent_id=? AND kind='stopped'", helper.id)["n"] == 1


def test_a_helpers_identity_says_its_model_so_records_never_mix():
    """Helpers were opencode-1, opencode-2... whatever model they ran: re-added with another model, a helper took over
    the old one's matches. The model is part of the identity now; the same model gets its name (and record) back."""
    name = agents.helper_name
    assert name("opencode", "deepseek/deepseek-v4.1-flash", set()) == "opencode-deepseek-v4.1-flash-1"
    assert name("opencode", "deepseek/deepseek-v4.1-flash", {"opencode-deepseek-v4.1-flash-1"}) == "opencode-deepseek-v4.1-flash-2"
    assert name("opencode", "muse-spark-1.3", {"opencode-deepseek-v4.1-flash-1"}) == "opencode-muse-spark-1.3-1"
    assert name("antigravity", None, set()) == "antigravity-1"
    long = name("antigravity", "Some Provider/A Very Long Model Name: Preview Edition 2026", set())
    assert len(long) <= 40 and all(c.isalnum() or c in "-_." for c in long)

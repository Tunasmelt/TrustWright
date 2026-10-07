from conftest import choose_fixture_intent
import json
import os
import select
import subprocess
import sys
import time

import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from trustwright.safety import MAX_FRAME


def parameters(s):
    args = [
        "-m",
        "trustwright",
        "serve",
        "--root",
        str(s.root),
        "--state-dir",
        str(s.state.directory.parent),
    ]
    if s.engine:
        args += ["--opengrep", s.engine]
    return StdioServerParameters(command=sys.executable, args=args)


def unpack(r):
    assert not r.isError, r.content
    return r.structuredContent


def test_mcp_end_to_end(service):
    async def run():
        seen = []

        async def approve(ctx, params):
            seen.append(params)
            return types.ElicitResult(action="accept", content={"approve": True})

        async with stdio_client(parameters(service)) as (read, write):
            async with ClientSession(read, write, elicitation_callback=approve) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert len(tools.tools) == 7
                assert len((await client.list_resources()).resources) == 1
                assert len((await client.list_resource_templates()).resourceTemplates) == 3
                assert len((await client.list_prompts()).prompts) == 3
                await client.read_resource("trustwright://controls")
                await client.read_resource("trustwright://schemas/report")
                await client.read_resource("trustwright://packs/fastapi-pyjwt-pwdlib")
                await client.read_resource("trustwright://recipes/fastapi-pyjwt-pwdlib/verify-token")
                await client.get_prompt("assess-project")
                d = unpack(await client.call_tool("detect_stack", {}))
                assert {x["name"] for x in d["dependencies"]} == {
                    "fastapi",
                    "pyjwt",
                    "pwdlib",
                }
                d = unpack(await client.call_tool("draft_intent", {}))
                assert all(r["status"] == "inferred" for r in d["requirements"])
                d = choose_fixture_intent(service)
                r = next(r for r in d["requirements"] if r["policy_kind"] == "authenticated")
                c = unpack(
                    await client.call_tool(
                        "confirm_intent",
                        {k: r[k] for k in ["endpoint_ref", "requirement_ref"]},
                    )
                )
                assert c["status"] == "approved" and len(seen) == 1
                assert seen[0].mode == "form"
                v = unpack(await client.call_tool("validate_intent", {}))
                assert v["valid"] and any(x["status"] == "confirmed" for x in v["requirements"])
                unpack(await client.call_tool("run_checks", {}))
                recipe = unpack(await client.call_tool("get_recipe", {}))
                assert recipe["tested_versions"]
                report = unpack(await client.call_tool("get_report", {}))
                assert len(report["unknowns"]) == 1 and "score" not in report
                if service.engine:
                    displays = [x["finding"]["display"] for x in report["current"][0]["findings"]]
                    assert {
                        "outcome": "needs_review",
                        "status": "pattern_matched",
                    } in displays
                    assert {
                        "outcome": "needs_review",
                        "status": "structurally_linked",
                    } in displays
                    # Same pack structural logic, explicit wrong dependency -> Not linked, never violated.
                    unpack(
                        await client.call_tool(
                            "run_checks",
                            {
                                "bindings": [
                                    {
                                        "endpoint_ref": r["endpoint_ref"],
                                        "requirement_ref": r["requirement_ref"],
                                        "dependency": "not_the_dependency",
                                    }
                                ]
                            },
                        )
                    )
                    report = unpack(await client.call_tool("get_report", {}))
                    assert any(
                        x["finding"]["display"]["status"] == "not_linked"
                        for x in report["current"][0]["findings"]
                    )
                bad = await client.call_tool("run_checks", {"command": "SECRET_DO_NOT_ECHO"})
                assert (
                    bad.isError
                    and "invalid_tool_input" in bad.content[0].text
                    and "SECRET" not in bad.content[0].text
                )

    anyio.run(run)


def test_mcp_fallback_pending(service):
    async def run():
        async with stdio_client(parameters(service)) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                d = unpack(await client.call_tool("draft_intent", {}))
                d = choose_fixture_intent(service)
                r = next(r for r in d["requirements"] if r["policy_kind"] == "authenticated")
                p = unpack(
                    await client.call_tool(
                        "confirm_intent",
                        {k: r[k] for k in ["endpoint_ref", "requirement_ref"]},
                    )
                )
                assert p["status"] == "pending" and p["fallback_command"].startswith(
                    "trustwright confirm "
                )
                assert not service.state.read()["ledger"]["intent_confirmations"]

    anyio.run(run)


def raw_exchange(service, data):
    p = parameters(service)
    child = subprocess.Popen(
        [p.command, *p.args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        child.stdin.write(data)
        child.stdin.flush()
        assert select.select([child.stdout], [], [], 15)[0], "boundary must respond"
        return json.loads(child.stdout.readline())
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def test_mcp_oversize_boundary(service):
    response = raw_exchange(service, b'{"payload":"' + b"x" * (MAX_FRAME + 10) + b'"}\n')
    assert "message_too_large" in response["error"]["message"]


def test_mcp_malformed_boundary(service):
    response = raw_exchange(
        service,
        b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_report","arguments":"SECRET"}}\n',
    )
    assert "malformed_tool_input" in response["error"]["message"] and "SECRET" not in json.dumps(
        response
    )


def test_cli_interactive_confirmation(service):
    import pty

    service.draft_intent()
    d = choose_fixture_intent(service)
    r = next(x for x in d["requirements"] if x["policy_kind"] == "authenticated")
    pending = service.prepare_confirmation(r["endpoint_ref"], r["requirement_ref"])
    master, slave = pty.openpty()
    child = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "trustwright",
            "confirm",
            pending["request_id"],
            "--root",
            str(service.root),
            "--state-dir",
            str(service.state.directory.parent),
        ],
        stdin=slave,
        stdout=slave,
        stderr=slave,
    )
    os.close(slave)
    try:
        data = b""
        deadline = time.monotonic() + 15
        while b"Type APPROVE" not in data and time.monotonic() < deadline:
            if select.select([master], [], [], 1)[0]:
                data += os.read(master, 8192)
        assert b"Type APPROVE" in data
        os.write(master, b"APPROVE\n")
        assert child.wait(timeout=10) == 0
        assert (
            service.state.read()["ledger"]["intent_confirmations"][0]["request_id"]
            == pending["request_id"]
        )
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
        os.close(master)

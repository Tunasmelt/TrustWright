"""Bounded line-delimited stdio transport; malformed values never reach SDK error formatting."""

import json
import sys
from contextlib import asynccontextmanager

import anyio
from mcp import types
from mcp.shared.message import SessionMessage

from .safety import MAX_FRAME, MAX_OUTPUT, Refused, strict_json


@asynccontextmanager
async def bounded_stdio():
    inbound, read = anyio.create_memory_object_stream(0)
    write, outbound = anyio.create_memory_object_stream(0)
    output_lock = anyio.Lock()

    async def emit(obj):
        data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode() + b"\n"
        if len(data) > MAX_OUTPUT:
            data = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": obj.get("id"),
                        "error": {
                            "code": -32603,
                            "message": "response_too_large: narrow the workspace",
                        },
                    }
                ).encode()
                + b"\n"
            )
        async with output_lock:
            await anyio.to_thread.run_sync(sys.stdout.buffer.write, data)
            await anyio.to_thread.run_sync(sys.stdout.buffer.flush)

    async def reader():
        async with inbound:
            while True:
                line = await anyio.to_thread.run_sync(
                    lambda: sys.stdin.buffer.readline(MAX_FRAME + 1),
                    abandon_on_cancel=True,
                )
                if not line:
                    break
                response_id = None
                try:
                    obj = strict_json(line)
                    if not isinstance(obj, dict):
                        raise Refused("malformed_request: object required")
                    if "id" in obj and not (
                        type(obj["id"]) is int
                        or isinstance(obj["id"], str)
                        and len(obj["id"]) <= 128
                    ):
                        raise Refused("malformed_request: invalid id")
                    response_id = obj.get("id")
                    if obj.get("method") == "tools/call":
                        params = obj.get("params")
                        if (
                            not isinstance(params, dict)
                            or not isinstance(params.get("name"), str)
                            or not isinstance(params.get("arguments", {}), dict)
                        ):
                            raise Refused(
                                "malformed_tool_input: expected name and object arguments"
                            )
                    try:
                        message = types.JSONRPCMessage.model_validate(obj)
                    except Exception:
                        raise Refused("malformed_request: invalid MCP message") from None
                    await inbound.send(SessionMessage(message))
                except Refused as e:
                    await emit(
                        {
                            "jsonrpc": "2.0",
                            "id": response_id,
                            "error": {"code": -32600, "message": str(e)},
                        }
                    )
                    if len(line) > MAX_FRAME:
                        break  # close session; never buffer/drain an unbounded frame

    async def writer():
        async with outbound:
            async for message in outbound:
                await emit(
                    message.message.model_dump(mode="json", by_alias=True, exclude_none=True)
                )

    async with anyio.create_task_group() as tg:
        tg.start_soon(reader)
        tg.start_soon(writer)
        try:
            yield read, write
        finally:
            tg.cancel_scope.cancel()

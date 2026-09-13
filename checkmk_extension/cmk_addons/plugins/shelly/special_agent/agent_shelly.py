#!/usr/bin/env python3
# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/agent_shelly.py
#
# Special agent for the shelly extension: queries each configured Shelly
# device's HTTP RPC API and reports its data as piggyback for that
# device's alias.
#
# Devices are fetched concurrently via asyncio (Shelly's HTTP transport
# doesn't support batching multiple RPC calls into one request, so this
# is the remaining lever for reducing wall-clock time with many
# devices). Fetching and writing are deliberately kept as two separate
# phases: writing piggyback sections requires switching stdout's
# "current piggyback target" via ConditionalPiggybackSection, which
# would corrupt the output if two devices' writes interleaved while
# both are mid-await. So every device is fully fetched first (network
# I/O only, no stdout writes), then results are written out one at a
# time, synchronously.

import asyncio
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import httpx
from cmk.special_agents.v0_unstable.agent_common import (
    ConditionalPiggybackSection,
    SectionWriter,
    special_agent_main,
)
from cmk.special_agents.v0_unstable.argument_parsing import (
    Args,
    create_default_argument_parser,
)

LOGGING = logging.getLogger("agent_shelly")


@dataclass(frozen=True)
class Device:
    alias: str
    host: str
    username: str
    password: str
    timeout: float = 10.0


class AsyncSessionManager:
    def __init__(self, username: str, password: str, timeout: float = 10) -> None:
        auth = httpx.DigestAuth(username, password) if username else None
        self._client = httpx.AsyncClient(auth=auth, timeout=timeout)

    async def get(self, url: str) -> Any:
        resp = await self._client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def parse_arguments(argv: Sequence[str] | None) -> Args:
    parser = create_default_argument_parser(description=__doc__)
    parser.add_argument("--device", action="append", default=[], dest="devices")
    parser.add_argument("--host", action="append", default=[], dest="hosts")
    parser.add_argument("--username", action="append", default=[], dest="usernames")
    parser.add_argument("--password", action="append", default=[], dest="passwords")
    parser.add_argument(
        "--timeout", action="append", default=[], dest="timeouts", type=float
    )
    return parser.parse_args(argv)


def devices_from_args(args: Args) -> list[Device]:
    return [
        Device(
            alias=alias,
            host=host,
            username=username,
            password=password,
            timeout=timeout,
        )
        for alias, host, username, password, timeout in zip(
            args.devices,
            args.hosts,
            args.usernames,
            args.passwords,
            args.timeouts,
        )
    ]


async def fetch_device(device: Device) -> dict[str, Any] | None:
    session = AsyncSessionManager(
        device.username,
        device.password,
        timeout=device.timeout,
    )
    base_url = f"http://{device.host}"
    try:
        device_info = await session.get(f"{base_url}/rpc/Shelly.GetDeviceInfo")
        status = await session.get(f"{base_url}/rpc/Shelly.GetStatus")
        ble_config = await session.get(f"{base_url}/rpc/Ble.GetConfig")

        # Only the per-input config, not the whole-device Shelly.GetConfig --
        # that includes WiFi/MQTT/cloud credentials in plaintext, which we
        # don't want piggybacked into Checkmk's monitoring data.
        input_config = {}
        for key in status:
            if key.startswith("input:"):
                input_id = key.split(":", 1)[1]
                input_config[key] = await session.get(
                    f"{base_url}/rpc/Input.GetConfig?id={input_id}"
                )
    except httpx.HTTPError as e:
        LOGGING.error("Failed to query %s (%s): %s", device.alias, device.host, e)
        return None
    finally:
        await session.aclose()
    return {
        "device_info": device_info,
        "status": status,
        "ble_config": ble_config,
        "input_config": input_config,
    }


async def fetch_all(devices: list[Device]) -> list[dict[str, Any] | None]:
    return await asyncio.gather(*(fetch_device(device) for device in devices))


def write_device(device: Device, data: dict[str, Any] | None) -> None:
    with ConditionalPiggybackSection(device.alias):
        if data is None:
            with SectionWriter("shelly_reachable") as w:
                w.append_json({"alias": device.alias, "reachable": False})
            return
        with SectionWriter("shelly_device_info") as w:
            w.append_json(data["device_info"])
        with SectionWriter("shelly_status") as w:
            w.append_json(data["status"])
        with SectionWriter("shelly_ble_config") as w:
            w.append_json(data["ble_config"])
        with SectionWriter("shelly_input_config") as w:
            w.append_json(data["input_config"])
        with SectionWriter("shelly_reachable") as w:
            w.append_json({"alias": device.alias, "reachable": True})


def agent_shelly_main(args: Args) -> int:
    devices = devices_from_args(args)
    results = asyncio.run(fetch_all(devices))
    for device, data in zip(devices, results):
        write_device(device, data)
    return 0


def main() -> int:
    return special_agent_main(parse_arguments, agent_shelly_main)


if __name__ == "__main__":
    sys.exit(main())

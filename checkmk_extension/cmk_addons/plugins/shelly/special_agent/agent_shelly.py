#!/usr/bin/env python3
# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/agent_shelly.py
#
# Special agent entrypoint for the shelly extension: parses CLI args,
# then fetches every configured device and writes its piggyback data.
# Fetch/write logic is generation-specific and lives in gen1.py / gen2.py;
# this module holds only what's shared -- CLI parsing and the async
# gather/write orchestration -- and dispatches to the right module per
# device.generation.
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
import sys
from collections.abc import Sequence
from typing import Any

from cmk.special_agents.v0_unstable.agent_common import special_agent_main
from cmk.special_agents.v0_unstable.argument_parsing import (
    Args,
    create_default_argument_parser,
)
from cmk_addons.plugins.shelly.special_agent import gen1, gen2
from cmk_addons.plugins.shelly.special_agent.devices import Device


def parse_arguments(argv: Sequence[str] | None) -> Args:
    parser = create_default_argument_parser(description=__doc__)
    parser.add_argument("--device", action="append", default=[], dest="devices")
    parser.add_argument("--generation", action="append", default=[], dest="generations")
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
            generation=generation,
            host=host,
            username=username,
            password=password,
            timeout=timeout,
        )
        for alias, generation, host, username, password, timeout in zip(
            args.devices,
            args.generations,
            args.hosts,
            args.usernames,
            args.passwords,
            args.timeouts,
        )
    ]


def _generation_module(generation: str) -> Any:
    if generation == "gen1":
        return gen1
    if generation == "gen2":
        return gen2
    raise ValueError(f"Unknown Shelly device generation: {generation!r}")


async def fetch_device(device: Device) -> dict[str, Any] | None:
    return await _generation_module(device.generation).fetch_device(device)


async def fetch_all(devices: list[Device]) -> list[dict[str, Any] | None]:
    return await asyncio.gather(*(fetch_device(device) for device in devices))


def write_device(device: Device, data: dict[str, Any] | None) -> None:
    _generation_module(device.generation).write_device(device, data)


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

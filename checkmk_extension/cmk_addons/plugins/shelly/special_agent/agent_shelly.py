#!/usr/bin/env python3
# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/agent_shelly.py
#
# Special agent for the shelly extension: queries each configured Shelly
# device's HTTP RPC API and reports its data as piggyback for that
# device's alias. Built iteratively -- this first version only calls
# Shelly.GetDeviceInfo; Shelly.GetStatus and Ble.GetConfig follow in
# later commits.

import base64
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import requests

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


class SessionManager:
    def __init__(self, username: str, password: str, timeout: int = 10) -> None:
        self._session = requests.Session()
        if username:
            auth_encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            self._session.headers.update({"Authorization": f"Basic {auth_encoded}"})
        self._timeout = timeout

    def get(self, url: str) -> Any:
        resp = self._session.get(url, timeout=self._timeout)
        resp.raise_for_status()
        return resp.json()


def parse_arguments(argv: Sequence[str] | None) -> Args:
    parser = create_default_argument_parser(description=__doc__)
    parser.add_argument("--device", action="append", default=[], dest="devices")
    parser.add_argument("--host", action="append", default=[], dest="hosts")
    parser.add_argument("--username", action="append", default=[], dest="usernames")
    parser.add_argument("--password", action="append", default=[], dest="passwords")
    return parser.parse_args(argv)


def devices_from_args(args: Args) -> list[Device]:
    return [
        Device(alias=alias, host=host, username=username, password=password)
        for alias, host, username, password in zip(
            args.devices, args.hosts, args.usernames, args.passwords
        )
    ]


def query_device(device: Device) -> None:
    session = SessionManager(device.username, device.password)
    base_url = f"http://{device.host}"

    with ConditionalPiggybackSection(device.alias):
        try:
            device_info = session.get(f"{base_url}/rpc/Shelly.GetDeviceInfo")
        except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
            LOGGING.error("Failed to query %s (%s): %s", device.alias, device.host, e)
            return
        with SectionWriter("shelly_device_info") as w:
            w.append_json(device_info)


def agent_shelly_main(args: Args) -> int:
    for device in devices_from_args(args):
        query_device(device)
    return 0


def main() -> int:
    return special_agent_main(parse_arguments, agent_shelly_main)


if __name__ == "__main__":
    sys.exit(main())

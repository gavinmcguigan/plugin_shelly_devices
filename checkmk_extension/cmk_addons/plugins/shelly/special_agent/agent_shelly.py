#!/usr/bin/env python3

import base64
import logging
import sys
from collections.abc import Sequence
from typing import Any

import requests

from cmk.special_agents.v0_unstable.agent_common import (
    SectionWriter,
    special_agent_main,
)
from cmk.special_agents.v0_unstable.argument_parsing import (
    Args,
    create_default_argument_parser,
)

LOGGING = logging.getLogger("agent_shelly")


class SessionManager:
    def __init__(
        self, username: str, password: str, timeout: int, no_cert_check: bool = False
    ) -> None:
        self._session = requests.Session()
        auth_encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        self._session.headers.update({"Authorization": f"Basic {auth_encoded}"})
        self._verify = bool(no_cert_check)
        self._timeout = timeout

    def get(self, url: str, params: dict[str, str] | None = None) -> Any:
        try:
            resp = self._session.get(
                url, params=params, verify=self._verify, timeout=self._timeout
            )
        except requests.exceptions.ConnectionError as e:
            LOGGING.error("Connection failed: %s", e)
            raise e

        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            LOGGING.error("HTTP error: %s", e)
            raise e

        return resp.json()


def parse_arguments(argv: Sequence[str] | None) -> Args:
    parser = create_default_argument_parser(description=__doc__)
    parser.add_argument(
        "-u", "--username", type=str, required=False, help="Username for login"
    )
    parser.add_argument(
        "-p", "--password", type=str, required=False, help="Password for login"
    )
    parser.add_argument(
        "-P", "--port", type=int, required=False, default=80, help="Port for connection"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds for network connects (default=10)",
    )
    parser.add_argument(
        "--no-cert-check",
        action="store_true",
        help="Disable verification of the servers ssl certificate",
    )
    parser.add_argument("host", help="Host name or IP address of the Shelly device")
    return parser.parse_args(argv)


def write_section(data: dict[str, Any], section_name: str) -> None:
    with SectionWriter(f"shelly_{section_name}") as w:
        w.append_json(data)


def agent_shelly_main(args: Args) -> int:
    """Establish a connection to a Shelly device and call the different endpoints to retrieve data"""
    session = SessionManager(
        args.username, args.password, args.timeout, args.no_cert_check
    )
    base_url = f"http://{args.host}:{args.port}"
    try:
        write_section(session.get(f"{base_url}/rpc/Shelly.GetDeviceInfo"), "device_info")
        write_section(session.get(f"{base_url}/rpc/Sys.GetStatus"), "system_status")
        write_section(session.get(f"{base_url}/rpc/Switch.GetStatus?id=0"), "switch_status")
    except (requests.exceptions.ConnectionError, requests.exceptions.HTTPError):
        return 1
    return 0


def main() -> int:
    """Main entry point to be used"""
    return special_agent_main(parse_arguments, agent_shelly_main)


if __name__ == "__main__":
    sys.exit(main())

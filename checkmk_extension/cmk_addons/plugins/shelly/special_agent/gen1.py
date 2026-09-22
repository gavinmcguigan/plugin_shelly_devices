# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/gen1.py
#
# Gen1 (legacy HTTP API, HTTP Basic auth) device fetch and piggyback-write
# logic. Orchestration (CLI parsing, async gather, entrypoint) lives in
# agent_shelly.py, which dispatches here per device.generation.
#
# Gen1's API shape is completely different from Gen2's RPC API: /shelly
# returns static identity info (type, mac, auth, firmware, mode), and
# /status returns everything else (wifi_sta, cloud, mqtt, lights[],
# meters[], inputs[], uptime, ...) in one call -- there's no per-item
# config endpoint to fetch separately like Gen2's Input.GetConfig/
# Switch.GetConfig.

import logging
from dataclasses import dataclass
from typing import Any

import httpx
from cmk.special_agents.v0_unstable.agent_common import (
    ConditionalPiggybackSection,
    SectionWriter,
)
from cmk_addons.plugins.shelly.special_agent.devices import Device

LOGGING = logging.getLogger("agent_shelly")


@dataclass(frozen=True)
class AuthenticationFailed:
    """fetch_device's result when the device returned HTTP 401 -- a device
    that requires Basic auth but wasn't given valid credentials. Kept
    distinct from a plain unreachable device (timeout, connection refused,
    ...) since this failure is a configuration problem that won't resolve
    on retry, unlike a transient network issue.
    """


class AsyncSessionManager:
    def __init__(self, username: str, password: str, timeout: float = 10) -> None:
        auth = httpx.BasicAuth(username, password) if username else None
        self._client = httpx.AsyncClient(auth=auth, timeout=timeout)

    async def get(self, url: str) -> Any:
        resp = await self._client.get(url)
        resp.raise_for_status()
        return resp.json()

    async def aclose(self) -> None:
        await self._client.aclose()


async def fetch_device(device: Device) -> dict[str, Any] | AuthenticationFailed | None:
    session = AsyncSessionManager(
        device.username,
        device.password,
        timeout=device.timeout,
    )
    base_url = f"http://{device.host}"
    try:
        identity = await session.get(f"{base_url}/shelly")
        status = await session.get(f"{base_url}/status")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            LOGGING.error(
                "Authentication failed for %s (%s)", device.alias, device.host
            )
            return AuthenticationFailed()
        LOGGING.error("Failed to query %s (%s): %s", device.alias, device.host, e)
        return None
    except httpx.HTTPError as e:
        LOGGING.error("Failed to query %s (%s): %s", device.alias, device.host, e)
        return None
    finally:
        await session.aclose()
    return {
        "identity": identity,
        "status": status,
    }


def write_device(
    device: Device,
    data: dict[str, Any] | AuthenticationFailed | None,
) -> None:
    with ConditionalPiggybackSection(device.alias):
        if isinstance(data, AuthenticationFailed):
            with SectionWriter("shelly_gen1_reachable") as w:
                w.append_json({"alias": device.alias, "reachability": "unauthorized"})
            return
        if data is None:
            with SectionWriter("shelly_gen1_reachable") as w:
                w.append_json({"alias": device.alias, "reachability": "unreachable"})
            return
        with SectionWriter("shelly_gen1_identity") as w:
            w.append_json(data["identity"])
        with SectionWriter("shelly_gen1_status") as w:
            w.append_json(data["status"])
        with SectionWriter("shelly_gen1_reachable") as w:
            w.append_json({"alias": device.alias, "reachability": "reachable"})

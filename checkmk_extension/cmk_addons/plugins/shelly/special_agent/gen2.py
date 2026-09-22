# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/special_agent/gen2.py
#
# Gen2 (RPC/JSON API, HTTP Digest auth) device fetch and piggyback-write
# logic. Orchestration (CLI parsing, async gather, entrypoint) lives in
# agent_shelly.py, which dispatches here per device.generation.

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
    that requires Digest auth but wasn't given valid credentials. Kept
    distinct from a plain unreachable device (timeout, connection refused,
    ...) since this failure is a configuration problem that won't resolve
    on retry, unlike a transient network issue.
    """


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


async def fetch_device(device: Device) -> dict[str, Any] | AuthenticationFailed | None:
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

        # Only the per-input/per-switch config, not the whole-device
        # Shelly.GetConfig -- that includes WiFi/MQTT/cloud credentials in
        # plaintext, which we don't want piggybacked into Checkmk's
        # monitoring data.
        input_config = {}
        for key in status:
            if key.startswith("input:"):
                input_id = key.split(":", 1)[1]
                input_config[key] = await session.get(
                    f"{base_url}/rpc/Input.GetConfig?id={input_id}"
                )

        switch_config = {}
        for key in status:
            if key.startswith("switch:"):
                switch_id = key.split(":", 1)[1]
                switch_config[key] = await session.get(
                    f"{base_url}/rpc/Switch.GetConfig?id={switch_id}"
                )
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
        "device_info": device_info,
        "status": status,
        "ble_config": ble_config,
        "input_config": input_config,
        "switch_config": switch_config,
    }


def write_device(
    device: Device,
    data: dict[str, Any] | AuthenticationFailed | None,
) -> None:
    with ConditionalPiggybackSection(device.alias):
        if isinstance(data, AuthenticationFailed):
            with SectionWriter("shelly_reachable") as w:
                w.append_json({"alias": device.alias, "reachability": "unauthorized"})
            return
        if data is None:
            with SectionWriter("shelly_reachable") as w:
                w.append_json({"alias": device.alias, "reachability": "unreachable"})
            return
        with SectionWriter("shelly_device_info") as w:
            w.append_json(data["device_info"])
        with SectionWriter("shelly_status") as w:
            w.append_json(data["status"])
        with SectionWriter("shelly_ble_config") as w:
            w.append_json(data["ble_config"])
        with SectionWriter("shelly_input_config") as w:
            w.append_json(data["input_config"])
        with SectionWriter("shelly_switch_config") as w:
            w.append_json(data["switch_config"])
        with SectionWriter("shelly_reachable") as w:
            w.append_json({"alias": device.alias, "reachability": "reachable"})

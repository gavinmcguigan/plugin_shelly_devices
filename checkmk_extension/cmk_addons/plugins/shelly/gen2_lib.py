# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/gen2_lib.py
#
# Shared types and helpers used across multiple Gen2 check plugins.
# Contains no agent_section_/check_plugin_/inventory_plugin_ objects
# itself -- those must live under agent_based/ to be discovered by
# Checkmk, so this is a plain library module imported by them.

from typing import Any, Literal, NotRequired, TypedDict

from cmk.agent_based.v2 import HostLabel, HostLabelGenerator, State

StatusSection = dict[str, Any]


class DeviceInfoSection(TypedDict):
    auth_en: bool
    mac: NotRequired[str]


class BleConfigSection(TypedDict):
    enable: bool


InputConfigSection = dict[str, Any]
SwitchConfigSection = dict[str, Any]


class ReachableSection(TypedDict):
    alias: str
    reachable: bool


def host_label_function_shelly_reachable(
    section: ReachableSection,
) -> HostLabelGenerator:
    yield HostLabel("shelly/alias", section["alias"])
    yield HostLabel("shelly/device", "yes")


Severity = Literal["ignore", "warn", "crit"]

_SEVERITY_STATE: dict[Severity, State] = {
    "ignore": State.OK,
    "warn": State.WARN,
    "crit": State.CRIT,
}


def _device_temperature_c(section: StatusSection) -> float | None:
    # Shared across every switch channel a device has (one physical
    # sensor) -- any channel's reading represents the whole device.
    for key, value in section.items():
        if key.startswith("switch:"):
            return value["temperature"]["tC"]
    return None


# Shelly's reset_reason isn't documented by Shelly itself, but observed
# values line up with Espressif's esp_reset_reason_t enum (these devices
# run on ESP32 hardware) -- see
# https://docs.espressif.com/projects/esp-idf/en/v4.4.3/esp32/api-reference/system/system.html
_RESET_REASON_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Power-on",
    2: "External reset",
    3: "Software reset",
    4: "Panic/exception",
    5: "Interrupt watchdog",
    6: "Task watchdog",
    7: "Other watchdog",
    8: "Deep sleep wake",
    9: "Brownout",
    10: "SDIO",
}
_UNEXPECTED_RESET_REASONS = {4, 5, 6, 7, 9}

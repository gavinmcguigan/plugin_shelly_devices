# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/shelly.py
#
# All check plugins for this extension: Reachability, Info,
# Connectivity, and per-switch-channel checks.

import json
from typing import Any, Literal, NotRequired, TypedDict

from cmk.agent_based.v2 import (
    AgentSection,
    Attributes,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    HostLabel,
    HostLabelGenerator,
    InventoryPlugin,
    InventoryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    TableRow,
    check_levels,
    get_value_store,
    render,
)
from cmk.rulesets.v1.form_specs import SimpleLevelsConfigModel

StatusSection = dict[str, Any]


def parse_shelly_status(string_table: StringTable) -> StatusSection:
    return json.loads(string_table[0][0])


agent_section_shelly_status = AgentSection(
    name="shelly_status",
    parse_function=parse_shelly_status,
)


class DeviceInfoSection(TypedDict):
    auth_en: bool
    mac: NotRequired[str]


def parse_shelly_device_info(string_table: StringTable) -> DeviceInfoSection:
    return json.loads(string_table[0][0])


agent_section_shelly_device_info = AgentSection(
    name="shelly_device_info",
    parse_function=parse_shelly_device_info,
)


class BleConfigSection(TypedDict):
    enable: bool


def parse_shelly_ble_config(string_table: StringTable) -> BleConfigSection:
    return json.loads(string_table[0][0])


agent_section_shelly_ble_config = AgentSection(
    name="shelly_ble_config",
    parse_function=parse_shelly_ble_config,
)


InputConfigSection = dict[str, Any]


def parse_shelly_input_config(string_table: StringTable) -> InputConfigSection:
    return json.loads(string_table[0][0])


agent_section_shelly_input_config = AgentSection(
    name="shelly_input_config",
    parse_function=parse_shelly_input_config,
)


class ReachableSection(TypedDict):
    alias: str
    reachable: bool


def parse_shelly_reachable(string_table: StringTable) -> ReachableSection:
    return json.loads(string_table[0][0])


def host_label_function_shelly_reachable(
    section: ReachableSection,
) -> HostLabelGenerator:
    yield HostLabel("shelly/alias", section["alias"])
    yield HostLabel("shelly/device", "yes")


agent_section_shelly_reachable = AgentSection(
    name="shelly_reachable",
    parse_function=parse_shelly_reachable,
    host_label_function=host_label_function_shelly_reachable,
)


def discover_shelly_reachable(section: ReachableSection) -> DiscoveryResult:
    yield Service()


class ReachabilityParams(TypedDict):
    failures_before_crit: int


def check_shelly_reachable(
    params: ReachabilityParams,
    section: ReachableSection,
) -> CheckResult:
    value_store = get_value_store()
    consecutive_failures = value_store.get("consecutive_failures", 0)

    if section["reachable"]:
        value_store["consecutive_failures"] = 0
        yield Result(state=State.OK, summary="Reachable")
        yield Metric("shelly_consecutive_failures", 0)
        return

    consecutive_failures += 1
    value_store["consecutive_failures"] = consecutive_failures
    yield Metric("shelly_consecutive_failures", consecutive_failures)

    threshold = params["failures_before_crit"]
    if consecutive_failures >= threshold:
        yield Result(
            state=State.CRIT,
            summary=f"Unreachable for {consecutive_failures} consecutive checks",
        )
    else:
        yield Result(
            state=State.WARN,
            summary=(
                f"Unreachable for {consecutive_failures} consecutive checks "
                f"(CRIT at {threshold})"
            ),
        )


check_plugin_shelly_reachable = CheckPlugin(
    name="shelly_reachable",
    service_name="Shelly Reachability",
    discovery_function=discover_shelly_reachable,
    check_function=check_shelly_reachable,
    check_ruleset_name="shelly_reachability",
    check_default_parameters=ReachabilityParams(failures_before_crit=3),
)


def discover_shelly_info(
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None:
        return
    yield Service()


Severity = Literal["ignore", "warn", "crit"]

_SEVERITY_STATE: dict[Severity, State] = {
    "ignore": State.OK,
    "warn": State.WARN,
    "crit": State.CRIT,
}


class InfoParams(TypedDict):
    temperature: SimpleLevelsConfigModel[float]
    wifi_signal: SimpleLevelsConfigModel[float]
    unset_password: Severity
    restart_required: Severity
    firmware_update_available: Severity
    unexpected_reboot: Severity


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


def check_shelly_info(
    params: InfoParams,
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> CheckResult:
    if section_shelly_status is None:
        return
    sys_status = section_shelly_status["sys"]

    uptime = sys_status["uptime"]
    yield Result(state=State.OK, summary=f"Up {render.timespan(uptime)}")
    yield Metric("uptime", uptime)

    if sys_status["restart_required"]:
        yield Result(
            state=_SEVERITY_STATE[params["restart_required"]],
            summary="Restart required",
        )
    else:
        yield Result(state=State.OK, summary="No restart required")

    if sys_status["available_updates"]:
        yield Result(
            state=_SEVERITY_STATE[params["firmware_update_available"]],
            summary="Firmware update available",
        )
    else:
        yield Result(state=State.OK, summary="Firmware up to date")

    if (reset_reason := sys_status.get("reset_reason")) is not None:
        reason_name = _RESET_REASON_NAMES.get(
            reset_reason, f"Unrecognized ({reset_reason})"
        )
        if reset_reason in _UNEXPECTED_RESET_REASONS:
            yield Result(
                state=_SEVERITY_STATE[params["unexpected_reboot"]],
                summary=f"Last reboot: {reason_name}",
            )
        else:
            yield Result(state=State.OK, summary=f"Last reboot: {reason_name}")

    if (temperature := _device_temperature_c(section_shelly_status)) is not None:
        yield from check_levels(
            temperature,
            label="Temperature",
            metric_name="temp",
            render_func=lambda v: f"{v:.1f} °C",
            levels_upper=params["temperature"],
        )

    if (rssi := section_shelly_status.get("wifi", {}).get("rssi")) is not None:
        yield from check_levels(
            rssi,
            label="WiFi signal",
            metric_name="shelly_wifi_rssi",
            render_func=lambda v: f"{v:.0f} dBm",
            levels_lower=params["wifi_signal"],
        )

    if section_shelly_device_info is not None:
        if section_shelly_device_info["auth_en"]:
            yield Result(state=State.OK, summary="Password protected")
        else:
            yield Result(
                state=_SEVERITY_STATE[params["unset_password"]],
                summary="Password not set",
            )


check_plugin_shelly_info = CheckPlugin(
    name="shelly_info",
    sections=["shelly_status", "shelly_device_info"],
    service_name="Shelly Info",
    discovery_function=discover_shelly_info,
    check_function=check_shelly_info,
    check_ruleset_name="shelly_info",
    check_default_parameters=InfoParams(
        temperature=("fixed", (70.0, 80.0)),
        wifi_signal=("fixed", (-70.0, -80.0)),
        unset_password="ignore",
        restart_required="warn",
        firmware_update_available="warn",
        unexpected_reboot="warn",
    ),
)


def inventorize_shelly_wifi(
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> InventoryResult:
    if section_shelly_status is None:
        return
    wifi = section_shelly_status.get("wifi", {})

    if ip_address := wifi.get("sta_ip"):
        yield TableRow(
            path=["networking", "addresses"],
            key_columns={"address": ip_address, "device": "wifi"},
            inventory_columns={"type": "ipv4"},
        )

    wlan_attributes: dict[str, str] = {}
    if ssid := wifi.get("ssid"):
        wlan_attributes["ssid"] = ssid
    if bssid := wifi.get("bssid"):
        wlan_attributes["access_point_mac"] = bssid
    if section_shelly_device_info is not None and (
        mac := section_shelly_device_info.get("mac")
    ):
        wlan_attributes["mac_address"] = mac
    if wlan_attributes:
        yield Attributes(
            path=["networking", "wlan"], inventory_attributes=wlan_attributes
        )


inventory_plugin_shelly_wifi = InventoryPlugin(
    name="shelly_wifi",
    sections=["shelly_status", "shelly_device_info"],
    inventory_function=inventorize_shelly_wifi,
)

Expectation = Literal["enabled", "disabled", "ignore"]


class ConnectivityParams(TypedDict):
    bluetooth: Expectation
    mqtt: Expectation
    cloud: Expectation
    websocket: Expectation


def discover_shelly_connectivity(
    section_shelly_status: StatusSection | None,
    section_shelly_ble_config: BleConfigSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None or section_shelly_ble_config is None:
        return
    yield Service()


def _check_expectation(label: str, actual: bool, expected: Expectation) -> Result:
    actual_str = "enabled" if actual else "disabled"
    if expected == "ignore" or expected == actual_str:
        return Result(state=State.OK, summary=f"{label}: {actual_str}")
    return Result(
        state=State.WARN,
        summary=f"{label}: {actual_str} (expected {expected})",
    )


def check_shelly_connectivity(
    params: ConnectivityParams,
    section_shelly_status: StatusSection | None,
    section_shelly_ble_config: BleConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None or section_shelly_ble_config is None:
        return

    bluetooth_enabled = section_shelly_ble_config["enable"]
    mqtt_connected = section_shelly_status["mqtt"]["connected"]
    cloud_connected = section_shelly_status["cloud"]["connected"]
    websocket_connected = section_shelly_status["ws"]["connected"]

    yield _check_expectation("Bluetooth", bluetooth_enabled, params["bluetooth"])
    yield Metric("shelly_bluetooth_enabled", 1.0 if bluetooth_enabled else 0.0)

    yield _check_expectation("MQTT", mqtt_connected, params["mqtt"])
    yield Metric("shelly_mqtt_connected", 1.0 if mqtt_connected else 0.0)

    yield _check_expectation("Cloud", cloud_connected, params["cloud"])
    yield Metric("shelly_cloud_connected", 1.0 if cloud_connected else 0.0)

    yield _check_expectation("Websocket", websocket_connected, params["websocket"])
    yield Metric("shelly_websocket_connected", 1.0 if websocket_connected else 0.0)


check_plugin_shelly_connectivity = CheckPlugin(
    name="shelly_connectivity",
    sections=["shelly_status", "shelly_ble_config"],
    service_name="Shelly Connectivity",
    discovery_function=discover_shelly_connectivity,
    check_function=check_shelly_connectivity,
    check_ruleset_name="shelly_connectivity",
    check_default_parameters=ConnectivityParams(
        bluetooth="ignore",
        mqtt="ignore",
        cloud="ignore",
        websocket="ignore",
    ),
)


def discover_shelly_switch(section: StatusSection) -> DiscoveryResult:
    for key in section:
        if key.startswith("switch:"):
            yield Service(item=key.split(":", 1)[1])


class SwitchParams(TypedDict):
    power: SimpleLevelsConfigModel[float]
    current: SimpleLevelsConfigModel[float]


def check_shelly_switch(
    item: str,
    params: SwitchParams,
    section: StatusSection,
) -> CheckResult:
    switch = section.get(f"switch:{item}")
    if switch is None:
        return

    yield Result(
        state=State.OK, summary=f"Relay: {'On' if switch['output'] else 'Off'}"
    )
    yield Metric("shelly_voltage", switch["voltage"])
    yield Metric("shelly_energy_total", switch["aenergy"]["total"])

    yield from check_levels(
        switch["apower"],
        label="Power",
        metric_name="shelly_power",
        render_func=lambda v: f"{v:.1f} W",
        levels_upper=params["power"],
    )
    yield from check_levels(
        switch["current"],
        label="Current",
        metric_name="shelly_current",
        render_func=lambda v: f"{v:.2f} A",
        levels_upper=params["current"],
    )


check_plugin_shelly_switch = CheckPlugin(
    name="shelly_switch",
    sections=["shelly_status"],
    service_name="Shelly Switch %s",
    discovery_function=discover_shelly_switch,
    check_function=check_shelly_switch,
    check_ruleset_name="shelly_switch",
    check_default_parameters=SwitchParams(
        power=("fixed", (2000.0, 2500.0)),
        current=("fixed", (10.0, 13.0)),
    ),
)


def discover_shelly_input(
    section_shelly_status: StatusSection | None,
    section_shelly_input_config: InputConfigSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None:
        return
    for key in section_shelly_status:
        if key.startswith("input:"):
            yield Service(item=key.split(":", 1)[1])


def check_shelly_input(
    item: str,
    section_shelly_status: StatusSection | None,
    section_shelly_input_config: InputConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None:
        return
    input_ = section_shelly_status.get(f"input:{item}")
    if input_ is None:
        return

    input_type = None
    if section_shelly_input_config is not None:
        input_type = section_shelly_input_config.get(f"input:{item}", {}).get("type")
    label = f"Input ({input_type.capitalize()})" if input_type else "Input"

    state = input_.get("state")
    if state is None:
        yield Result(state=State.OK, summary=f"{label}: No state reported")
        return

    yield Result(state=State.OK, summary=f"{label}: {'On' if state else 'Off'}")
    yield Metric("shelly_input_state", 1.0 if state else 0.0)


check_plugin_shelly_input = CheckPlugin(
    name="shelly_input",
    sections=["shelly_status", "shelly_input_config"],
    service_name="Shelly Input %s",
    discovery_function=discover_shelly_input,
    check_function=check_shelly_input,
)

# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/shelly.py
#
# All check plugins for this extension: Reachability, Info,
# Connectivity, and per-switch-channel checks.

import json
from typing import Any, Literal, TypedDict

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    HostLabel,
    HostLabelGenerator,
    Metric,
    Result,
    Service,
    State,
    StringTable,
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


class TemperatureParams(TypedDict):
    temperature: SimpleLevelsConfigModel[float]
    unset_password: Severity
    restart_required: Severity
    firmware_update_available: Severity


def _device_temperature_c(section: StatusSection) -> float | None:
    # Shared across every switch channel a device has (one physical
    # sensor) -- any channel's reading represents the whole device.
    for key, value in section.items():
        if key.startswith("switch:"):
            return value["temperature"]["tC"]
    return None


def check_shelly_info(
    params: TemperatureParams,
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

    if (temperature := _device_temperature_c(section_shelly_status)) is not None:
        yield from check_levels(
            temperature,
            label="Temperature",
            metric_name="temp",
            render_func=lambda v: f"{v:.1f} °C",
            levels_upper=params["temperature"],
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
    check_ruleset_name="shelly_temperature",
    check_default_parameters=TemperatureParams(
        temperature=("fixed", (70.0, 80.0)),
        unset_password="ignore",
        restart_required="warn",
        firmware_update_available="warn",
    ),
)

Expectation = Literal["enabled", "disabled", "ignore"]


class ConnectivityParams(TypedDict):
    bluetooth: Expectation
    mqtt: Expectation
    cloud: Expectation


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

    yield _check_expectation("Bluetooth", bluetooth_enabled, params["bluetooth"])
    yield Metric("shelly_bluetooth_enabled", 1.0 if bluetooth_enabled else 0.0)

    yield _check_expectation("MQTT", mqtt_connected, params["mqtt"])
    yield Metric("shelly_mqtt_connected", 1.0 if mqtt_connected else 0.0)

    yield _check_expectation("Cloud", cloud_connected, params["cloud"])
    yield Metric("shelly_cloud_connected", 1.0 if cloud_connected else 0.0)


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

    yield Result(state=State.OK, summary="On" if switch["output"] else "Off")
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

# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/shelly.py
#
# Reachability, Info, and Connectivity check plugins for this extension.
# Per-switch checks follow in a later commit.

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
    get_value_store,
    render,
)

StatusSection = dict[str, Any]


def parse_shelly_status(string_table: StringTable) -> StatusSection:
    return json.loads(string_table[0][0])


agent_section_shelly_status = AgentSection(
    name="shelly_status",
    parse_function=parse_shelly_status,
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


def host_label_function_shelly_reachable(section: ReachableSection) -> HostLabelGenerator:
    yield HostLabel("shelly/alias", section["alias"])


agent_section_shelly_reachable = AgentSection(
    name="shelly_reachable",
    parse_function=parse_shelly_reachable,
    host_label_function=host_label_function_shelly_reachable,
)


def discover_shelly_reachable(section: ReachableSection) -> DiscoveryResult:
    yield Service()


class ReachabilityParams(TypedDict):
    failures_before_crit: int


def check_shelly_reachable(params: ReachabilityParams, section: ReachableSection) -> CheckResult:
    value_store = get_value_store()
    consecutive_failures = value_store.get("consecutive_failures", 0)

    if section["reachable"]:
        value_store["consecutive_failures"] = 0
        yield Result(state=State.OK, summary="Reachable")
        return

    consecutive_failures += 1
    value_store["consecutive_failures"] = consecutive_failures

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


def discover_shelly_info(section: StatusSection) -> DiscoveryResult:
    yield Service()


def check_shelly_info(section: StatusSection) -> CheckResult:
    sys_status = section["sys"]

    uptime = sys_status["uptime"]
    yield Result(state=State.OK, summary=f"Up {render.timespan(uptime)}")
    yield Metric("uptime", uptime)

    if sys_status["restart_required"]:
        yield Result(state=State.WARN, summary="Restart required")
    else:
        yield Result(state=State.OK, summary="No restart required")

    if sys_status["available_updates"]:
        yield Result(state=State.WARN, summary="Firmware update available")
    else:
        yield Result(state=State.OK, summary="Firmware up to date")


check_plugin_shelly_info = CheckPlugin(
    name="shelly_info",
    sections=["shelly_status"],
    service_name="Shelly Info",
    discovery_function=discover_shelly_info,
    check_function=check_shelly_info,
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
    return Result(state=State.WARN, summary=f"{label}: {actual_str} (expected {expected})")


def check_shelly_connectivity(
    params: ConnectivityParams,
    section_shelly_status: StatusSection | None,
    section_shelly_ble_config: BleConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None or section_shelly_ble_config is None:
        return
    yield _check_expectation("Bluetooth", section_shelly_ble_config["enable"], params["bluetooth"])
    yield _check_expectation("MQTT", section_shelly_status["mqtt"]["connected"], params["mqtt"])
    yield _check_expectation("Cloud", section_shelly_status["cloud"]["connected"], params["cloud"])


check_plugin_shelly_connectivity = CheckPlugin(
    name="shelly_connectivity",
    sections=["shelly_status", "shelly_ble_config"],
    service_name="Shelly Connectivity",
    discovery_function=discover_shelly_connectivity,
    check_function=check_shelly_connectivity,
    check_ruleset_name="shelly_connectivity",
    check_default_parameters=ConnectivityParams(bluetooth="ignore", mqtt="ignore", cloud="ignore"),
)

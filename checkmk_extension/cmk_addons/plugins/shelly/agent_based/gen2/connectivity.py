# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/connectivity.py

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
)
from cmk_addons.plugins.shelly.agent_based.gen2.defaults import (
    GEN2_SETTINGS_DEFAULT_PARAMETERS,
    Expectation,
    Gen2SettingsParams,
)
from cmk_addons.plugins.shelly.lib import BleConfigSection, StatusSection


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
    params: Gen2SettingsParams,
    section_shelly_status: StatusSection | None,
    section_shelly_ble_config: BleConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None or section_shelly_ble_config is None:
        return
    connectivity_params = params["connectivity"]

    bluetooth_enabled = section_shelly_ble_config["enable"]
    mqtt_connected = section_shelly_status["mqtt"]["connected"]
    cloud_connected = section_shelly_status["cloud"]["connected"]
    websocket_connected = section_shelly_status["ws"]["connected"]

    yield _check_expectation(
        "Bluetooth", bluetooth_enabled, connectivity_params["bluetooth"]
    )
    yield Metric("shelly_bluetooth_enabled", 1.0 if bluetooth_enabled else 0.0)

    yield _check_expectation("MQTT", mqtt_connected, connectivity_params["mqtt"])
    yield Metric("shelly_mqtt_connected", 1.0 if mqtt_connected else 0.0)

    yield _check_expectation("Cloud", cloud_connected, connectivity_params["cloud"])
    yield Metric("shelly_cloud_connected", 1.0 if cloud_connected else 0.0)

    yield _check_expectation(
        "Websocket", websocket_connected, connectivity_params["websocket"]
    )
    yield Metric("shelly_websocket_connected", 1.0 if websocket_connected else 0.0)


check_plugin_shelly_connectivity = CheckPlugin(
    name="shelly_connectivity",
    sections=["shelly_status", "shelly_ble_config"],
    service_name="Shelly Connectivity",
    discovery_function=discover_shelly_connectivity,
    check_function=check_shelly_connectivity,
    check_ruleset_name="shelly_gen2_settings",
    check_default_parameters=GEN2_SETTINGS_DEFAULT_PARAMETERS,
)

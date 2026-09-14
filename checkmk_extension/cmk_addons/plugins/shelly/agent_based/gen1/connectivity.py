# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/connectivity.py
#
# Gen1 only exposes Cloud and MQTT connectivity -- unlike Gen2, there's
# no Bluetooth or Websocket to report on.

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
)
from cmk_addons.plugins.shelly.agent_based.gen1.defaults import (
    GEN1_SETTINGS_DEFAULT_PARAMETERS,
    Expectation,
    Gen1SettingsParams,
)
from cmk_addons.plugins.shelly.gen1_lib import StatusSection


def discover_shelly_gen1_connectivity(
    section: StatusSection | None,
) -> DiscoveryResult:
    if section is None:
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


def check_shelly_gen1_connectivity(
    params: Gen1SettingsParams,
    section: StatusSection | None,
) -> CheckResult:
    if section is None:
        return
    connectivity_params = params["connectivity"]

    cloud_connected = section["cloud"]["connected"]
    mqtt_connected = section["mqtt"]["connected"]

    yield _check_expectation("Cloud", cloud_connected, connectivity_params["cloud"])
    yield Metric("shelly_cloud_connected", 1.0 if cloud_connected else 0.0)

    yield _check_expectation("MQTT", mqtt_connected, connectivity_params["mqtt"])
    yield Metric("shelly_mqtt_connected", 1.0 if mqtt_connected else 0.0)


check_plugin_shelly_gen1_connectivity = CheckPlugin(
    name="shelly_gen1_connectivity",
    sections=["shelly_gen1_status"],
    service_name="Shelly Connectivity",
    discovery_function=discover_shelly_gen1_connectivity,
    check_function=check_shelly_gen1_connectivity,
    check_ruleset_name="shelly_gen1_settings",
    check_default_parameters=GEN1_SETTINGS_DEFAULT_PARAMETERS,
)

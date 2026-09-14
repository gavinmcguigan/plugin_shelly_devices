# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/light.py
#
# One item per entry in /status's "lights" list. RGB is only meaningful
# when that light's own "mode" is "color" -- some Gen1 light devices
# (e.g. plain dimmers) only ever report "white", so this must be checked
# per-light rather than assumed for the whole device.

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    check_levels,
    render,
)
from cmk_addons.plugins.shelly.agent_based.gen1.defaults import (
    GEN1_SETTINGS_DEFAULT_PARAMETERS,
    Gen1SettingsParams,
)
from cmk_addons.plugins.shelly.gen1_lib import StatusSection


def discover_shelly_gen1_light(
    section: StatusSection | None,
) -> DiscoveryResult:
    if section is None:
        return
    for index in range(len(section.get("lights", []))):
        yield Service(item=str(index))


def check_shelly_gen1_light(
    item: str,
    params: Gen1SettingsParams,
    section: StatusSection | None,
) -> CheckResult:
    if section is None:
        return
    light_params = params["light"]

    lights = section.get("lights", [])
    if not item.isdigit() or int(item) >= len(lights):
        return
    light = lights[int(item)]

    yield Result(state=State.OK, summary=f"Light: {'On' if light['ison'] else 'Off'}")

    if (gain := light.get("gain")) is not None:
        yield Result(state=State.OK, summary=f"Brightness: {gain}%")
        yield Metric("shelly_gain", gain)

    if light.get("mode") == "color":
        red, green, blue = light.get("red"), light.get("green"), light.get("blue")
        if red is not None and green is not None and blue is not None:
            yield Result(state=State.OK, summary=f"RGB: ({red}, {green}, {blue})")
        if (white := light.get("white")) is not None:
            yield Result(state=State.OK, summary=f"White: {white}")

    if light.get("has_timer"):
        remaining = light.get("timer_remaining", 0)
        yield Result(
            state=State.OK,
            summary=f"Auto-off in {render.timespan(remaining)}",
        )

    meters = section.get("meters", [])
    if int(item) < len(meters):
        meter = meters[int(item)]
        if (power := meter.get("power")) is not None:
            yield from check_levels(
                power,
                label="Power",
                metric_name="shelly_power",
                render_func=lambda v: f"{v:.1f} W",
                levels_upper=light_params["power"],
            )
        if (total := meter.get("total")) is not None:
            yield Metric("shelly_energy_total", total)


check_plugin_shelly_gen1_light = CheckPlugin(
    name="shelly_gen1_light",
    sections=["shelly_gen1_status"],
    service_name="Shelly Light %s",
    discovery_function=discover_shelly_gen1_light,
    check_function=check_shelly_gen1_light,
    check_ruleset_name="shelly_gen1_settings",
    check_default_parameters=GEN1_SETTINGS_DEFAULT_PARAMETERS,
)

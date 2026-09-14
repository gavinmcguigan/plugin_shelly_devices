# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/switch.py

from typing import Any

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
from cmk_addons.plugins.shelly.agent_based.gen2.defaults import (
    GEN2_SETTINGS_DEFAULT_PARAMETERS,
    Gen2SettingsParams,
)
from cmk_addons.plugins.shelly.lib import (
    _SEVERITY_STATE,
    StatusSection,
    SwitchConfigSection,
)


def discover_shelly_switch(
    section_shelly_status: StatusSection | None,
    section_shelly_switch_config: SwitchConfigSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None:
        return
    for key in section_shelly_status:
        if key.startswith("switch:"):
            yield Service(item=key.split(":", 1)[1])


def _switch_timer_remaining(switch: dict[str, Any], now: int) -> float | None:
    timer_started_at = switch.get("timer_started_at")
    if not timer_started_at:
        return None
    remaining = (timer_started_at + switch.get("timer_duration", 0)) - now
    return remaining if remaining > 0 else None


def check_shelly_switch(
    item: str,
    params: Gen2SettingsParams,
    section_shelly_status: StatusSection | None,
    section_shelly_switch_config: SwitchConfigSection | None,
) -> CheckResult:
    if section_shelly_status is None:
        return
    switch_params = params["switch"]
    switch = section_shelly_status.get(f"switch:{item}")
    if switch is None:
        return

    name = None
    if section_shelly_switch_config is not None:
        name = section_shelly_switch_config.get(f"switch:{item}", {}).get("name")
    label = f"Relay ({name})" if name else "Relay"

    yield Result(
        state=State.OK, summary=f"{label}: {'On' if switch['output'] else 'Off'}"
    )

    timer_remaining = _switch_timer_remaining(
        switch, section_shelly_status["sys"]["unixtime"]
    )
    if timer_remaining is not None:
        yield Result(
            state=State.OK, summary=f"Auto-off in {render.timespan(timer_remaining)}"
        )

    if section_shelly_switch_config is not None:
        config = section_shelly_switch_config.get(f"switch:{item}", {})
        if config.get("auto_off"):
            delay = render.timespan(config.get("auto_off_delay", 0))
            yield Result(state=State.OK, summary=f"Auto-off timer configured ({delay})")
        else:
            yield Result(
                state=_SEVERITY_STATE[switch_params["missing_auto_off_timer"]],
                summary="Auto-off timer not configured",
            )

    yield Metric("shelly_voltage", switch["voltage"])
    yield Metric("shelly_energy_total", switch["aenergy"]["total"])

    yield from check_levels(
        switch["apower"],
        label="Power",
        metric_name="shelly_power",
        render_func=lambda v: f"{v:.1f} W",
        levels_upper=switch_params["power"],
    )
    yield from check_levels(
        switch["current"],
        label="Current",
        metric_name="shelly_current",
        render_func=lambda v: f"{v:.2f} A",
        levels_upper=switch_params["current"],
    )


check_plugin_shelly_switch = CheckPlugin(
    name="shelly_switch",
    sections=["shelly_status", "shelly_switch_config"],
    service_name="Shelly Relay %s",
    discovery_function=discover_shelly_switch,
    check_function=check_shelly_switch,
    check_ruleset_name="shelly_gen2_settings",
    check_default_parameters=GEN2_SETTINGS_DEFAULT_PARAMETERS,
)

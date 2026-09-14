# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/info.py
#
# Gen1's /status has no restart_required or reset_reason fields like
# Gen2's Shelly.GetStatus does, so this check is narrower than Gen2's
# equivalent: uptime, IP, WiFi signal, password, and firmware update
# availability only.

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
from cmk_addons.plugins.shelly.gen1_lib import (
    _SEVERITY_STATE,
    IdentitySection,
    StatusSection,
)


def discover_shelly_gen1_info(
    section_shelly_gen1_status: StatusSection | None,
    section_shelly_gen1_identity: IdentitySection | None,
) -> DiscoveryResult:
    if section_shelly_gen1_status is None:
        return
    yield Service()


def check_shelly_gen1_info(
    params: Gen1SettingsParams,
    section_shelly_gen1_status: StatusSection | None,
    section_shelly_gen1_identity: IdentitySection | None,
) -> CheckResult:
    if section_shelly_gen1_status is None:
        return
    info_params = params["info"]

    uptime = section_shelly_gen1_status["uptime"]
    yield Result(state=State.OK, summary=f"Up {render.timespan(uptime)}")
    yield Metric("uptime", uptime)

    wifi_sta = section_shelly_gen1_status.get("wifi_sta", {})
    if ip_address := wifi_sta.get("ip"):
        yield Result(state=State.OK, summary=f"IP: {ip_address}")

    if section_shelly_gen1_status.get("has_update"):
        yield Result(
            state=_SEVERITY_STATE[info_params["firmware_update_available"]],
            summary="Firmware update available",
        )
    else:
        yield Result(state=State.OK, summary="Firmware up to date")

    if (rssi := wifi_sta.get("rssi")) is not None:
        yield from check_levels(
            rssi,
            label="WiFi signal",
            metric_name="shelly_wifi_rssi",
            render_func=lambda v: f"{v:.0f} dBm",
            levels_lower=info_params["wifi_signal"],
        )

    if section_shelly_gen1_identity is not None:
        if section_shelly_gen1_identity["auth"]:
            yield Result(state=State.OK, summary="Password protected")
        else:
            yield Result(
                state=_SEVERITY_STATE[info_params["unset_password"]],
                summary="Password not set",
            )


check_plugin_shelly_gen1_info = CheckPlugin(
    name="shelly_gen1_info",
    sections=["shelly_gen1_status", "shelly_gen1_identity"],
    service_name="Shelly Info",
    discovery_function=discover_shelly_gen1_info,
    check_function=check_shelly_gen1_info,
    check_ruleset_name="shelly_gen1_settings",
    check_default_parameters=GEN1_SETTINGS_DEFAULT_PARAMETERS,
)

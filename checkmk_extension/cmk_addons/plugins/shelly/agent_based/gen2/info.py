# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/info.py

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
from cmk_addons.plugins.shelly.gen2_lib import (
    _RESET_REASON_NAMES,
    _SEVERITY_STATE,
    _UNEXPECTED_RESET_REASONS,
    DeviceInfoSection,
    StatusSection,
    _device_temperature_c,
)


def discover_shelly_info(
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> DiscoveryResult:
    if section_shelly_status is None:
        return
    yield Service()


def check_shelly_info(
    params: Gen2SettingsParams,
    section_shelly_status: StatusSection | None,
    section_shelly_device_info: DeviceInfoSection | None,
) -> CheckResult:
    if section_shelly_status is None:
        return
    info_params = params["info"]
    sys_status = section_shelly_status["sys"]

    uptime = sys_status["uptime"]
    yield Result(state=State.OK, summary=f"Up {render.timespan(uptime)}")
    yield Metric("uptime", uptime)

    if ip_address := section_shelly_status.get("wifi", {}).get("sta_ip"):
        yield Result(state=State.OK, summary=f"IP: {ip_address}")

    if sys_status["restart_required"]:
        yield Result(
            state=_SEVERITY_STATE[info_params["restart_required"]],
            summary="Restart required",
        )
    else:
        yield Result(state=State.OK, summary="No restart required")

    if sys_status["available_updates"]:
        yield Result(
            state=_SEVERITY_STATE[info_params["firmware_update_available"]],
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
                state=_SEVERITY_STATE[info_params["unexpected_reboot"]],
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
            levels_upper=info_params["temperature"],
        )

    if (rssi := section_shelly_status.get("wifi", {}).get("rssi")) is not None:
        yield from check_levels(
            rssi,
            label="WiFi signal",
            metric_name="shelly_wifi_rssi",
            render_func=lambda v: f"{v:.0f} dBm",
            levels_lower=info_params["wifi_signal"],
        )

    if section_shelly_device_info is not None:
        if section_shelly_device_info["auth_en"]:
            yield Result(state=State.OK, summary="Password protected")
        else:
            yield Result(
                state=_SEVERITY_STATE[info_params["unset_password"]],
                summary="Password not set",
            )


check_plugin_shelly_info = CheckPlugin(
    name="shelly_info",
    sections=["shelly_status", "shelly_device_info"],
    service_name="Shelly Info",
    discovery_function=discover_shelly_info,
    check_function=check_shelly_info,
    check_ruleset_name="shelly_gen2_settings",
    check_default_parameters=GEN2_SETTINGS_DEFAULT_PARAMETERS,
)

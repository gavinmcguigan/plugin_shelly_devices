# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen2/defaults.py
#
# All four Gen2 check plugins share one ruleset ("Shelly Gen2 settings"), so
# Checkmk hands each of them the *whole* params dict, not just their own
# section. The per-section TypedDicts and their combined shape both live
# here, rather than in each check plugin's own module, so that this module
# can build the combined default value without importing back from the
# check plugins (which import this module for their default).
from typing import Literal, TypedDict

from cmk.rulesets.v1.form_specs import SimpleLevelsConfigModel
from cmk_addons.plugins.shelly.gen2_lib import Severity

Expectation = Literal["enabled", "disabled", "ignore"]


class ReachabilityParams(TypedDict):
    failures_before_crit: int


class ConnectivityParams(TypedDict):
    bluetooth: Expectation
    mqtt: Expectation
    cloud: Expectation
    websocket: Expectation


class InfoParams(TypedDict):
    temperature: SimpleLevelsConfigModel[float]
    wifi_signal: SimpleLevelsConfigModel[float]
    unset_password: Severity
    restart_required: Severity
    firmware_update_available: Severity
    unexpected_reboot: Severity


class SwitchParams(TypedDict):
    power: SimpleLevelsConfigModel[float]
    current: SimpleLevelsConfigModel[float]
    missing_auto_off_timer: Severity


class Gen2SettingsParams(TypedDict):
    reachability: ReachabilityParams
    connectivity: ConnectivityParams
    info: InfoParams
    switch: SwitchParams


GEN2_SETTINGS_DEFAULT_PARAMETERS = Gen2SettingsParams(
    reachability=ReachabilityParams(failures_before_crit=3),
    connectivity=ConnectivityParams(
        bluetooth="ignore",
        mqtt="ignore",
        cloud="ignore",
        websocket="ignore",
    ),
    info=InfoParams(
        temperature=("fixed", (70.0, 80.0)),
        wifi_signal=("fixed", (-70.0, -80.0)),
        unset_password="ignore",
        restart_required="warn",
        firmware_update_available="warn",
        unexpected_reboot="warn",
    ),
    switch=SwitchParams(
        power=("fixed", (2000.0, 2500.0)),
        current=("fixed", (10.0, 13.0)),
        missing_auto_off_timer="ignore",
    ),
)

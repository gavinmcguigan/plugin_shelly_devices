# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/defaults.py
#
# All Gen1 check plugins share one ruleset ("Shelly Gen1 settings"), so
# Checkmk hands each of them the *whole* params dict, not just their own
# section. The per-section TypedDicts and their combined shape both live
# here, rather than in each check plugin's own module, so that this module
# can build the combined default value without importing back from the
# check plugins (which import this module for their default).
from typing import Literal, TypedDict

from cmk.rulesets.v1.form_specs import SimpleLevelsConfigModel
from cmk_addons.plugins.shelly.gen1_lib import Severity

Expectation = Literal["enabled", "disabled", "ignore"]


class ReachabilityParams(TypedDict):
    failures_before_crit: int


class ConnectivityParams(TypedDict):
    cloud: Expectation
    mqtt: Expectation


class InfoParams(TypedDict):
    wifi_signal: SimpleLevelsConfigModel[float]
    unset_password: Severity
    firmware_update_available: Severity


class LightParams(TypedDict):
    power: SimpleLevelsConfigModel[float]


class Gen1SettingsParams(TypedDict):
    reachability: ReachabilityParams
    connectivity: ConnectivityParams
    info: InfoParams
    light: LightParams


GEN1_SETTINGS_DEFAULT_PARAMETERS = Gen1SettingsParams(
    reachability=ReachabilityParams(failures_before_crit=3),
    connectivity=ConnectivityParams(cloud="ignore", mqtt="ignore"),
    info=InfoParams(
        wifi_signal=("fixed", (-70.0, -80.0)),
        unset_password="ignore",
        firmware_update_available="warn",
    ),
    light=LightParams(
        power=("fixed", (2000.0, 2500.0)),
    ),
)

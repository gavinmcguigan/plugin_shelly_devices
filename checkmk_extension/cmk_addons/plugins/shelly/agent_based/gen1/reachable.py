# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/agent_based/gen1/reachable.py

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    get_value_store,
)
from cmk_addons.plugins.shelly.agent_based.gen1.defaults import (
    GEN1_SETTINGS_DEFAULT_PARAMETERS,
    Gen1SettingsParams,
)
from cmk_addons.plugins.shelly.gen1_lib import ReachableSection


def discover_shelly_gen1_reachable(section: ReachableSection) -> DiscoveryResult:
    yield Service()


def check_shelly_gen1_reachable(
    params: Gen1SettingsParams,
    section: ReachableSection,
) -> CheckResult:
    reachability_params = params["reachability"]
    value_store = get_value_store()
    consecutive_failures = value_store.get("consecutive_failures", 0)

    if section["reachability"] == "reachable":
        value_store["consecutive_failures"] = 0
        yield Result(state=State.OK, summary="Reachable")
        yield Metric("shelly_consecutive_failures", 0)
        return

    if section["reachability"] == "unauthorized":
        # A config problem, not a transient network issue -- won't resolve
        # on retry, so report it immediately instead of going through the
        # consecutive-failures threshold.
        yield Result(
            state=State.CRIT,
            summary="Authentication failed - check the configured username/password",
        )
        yield Metric("shelly_consecutive_failures", consecutive_failures)
        return

    consecutive_failures += 1
    value_store["consecutive_failures"] = consecutive_failures
    yield Metric("shelly_consecutive_failures", consecutive_failures)

    threshold = reachability_params["failures_before_crit"]
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


check_plugin_shelly_gen1_reachable = CheckPlugin(
    name="shelly_gen1_reachable",
    service_name="Shelly Reachability",
    discovery_function=discover_shelly_gen1_reachable,
    check_function=check_shelly_gen1_reachable,
    check_ruleset_name="shelly_gen1_settings",
    check_default_parameters=GEN1_SETTINGS_DEFAULT_PARAMETERS,
)

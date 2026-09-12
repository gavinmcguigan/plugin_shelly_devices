# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/graphing/shelly.py
#
# Metric definitions (name, unit, color) and a Perfometer for the
# per-switch metrics. Named shelly_* since metric names are global --
# bare names like "power"/"current" risk colliding with existing
# core checks (UPS/PDU, etc).

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import (
    Color,
    DecimalNotation,
    Metric,
    SINotation,
    StrictPrecision,
    Unit,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

metric_shelly_power = Metric(
    name="shelly_power",
    title=Title("Power"),
    unit=Unit(SINotation("W")),
    color=Color.ORANGE,
)

metric_shelly_current = Metric(
    name="shelly_current",
    title=Title("Current"),
    unit=Unit(DecimalNotation("A")),
    color=Color.YELLOW,
)

metric_shelly_voltage = Metric(
    name="shelly_voltage",
    title=Title("Voltage"),
    unit=Unit(DecimalNotation("V")),
    color=Color.BLUE,
)

metric_shelly_energy_total = Metric(
    name="shelly_energy_total",
    title=Title("Energy (total)"),
    unit=Unit(SINotation("Wh")),
    color=Color.PURPLE,
)

perfometer_shelly_power = Perfometer(
    name="shelly_power",
    focus_range=FocusRange(Closed(0), Open(1000)),
    segments=["shelly_power"],
)

metric_shelly_consecutive_failures = Metric(
    name="shelly_consecutive_failures",
    title=Title("Consecutive failed checks"),
    unit=Unit(DecimalNotation(""), StrictPrecision(0)),
    color=Color.RED,
)

metric_shelly_bluetooth_enabled = Metric(
    name="shelly_bluetooth_enabled",
    title=Title("Bluetooth enabled"),
    unit=Unit(DecimalNotation(""), StrictPrecision(0)),
    color=Color.LIGHT_BLUE,
)

metric_shelly_mqtt_connected = Metric(
    name="shelly_mqtt_connected",
    title=Title("MQTT connected"),
    unit=Unit(DecimalNotation(""), StrictPrecision(0)),
    color=Color.LIGHT_GREEN,
)

metric_shelly_cloud_connected = Metric(
    name="shelly_cloud_connected",
    title=Title("Cloud connected"),
    unit=Unit(DecimalNotation(""), StrictPrecision(0)),
    color=Color.LIGHT_PURPLE,
)

perfometer_shelly_consecutive_failures = Perfometer(
    name="shelly_consecutive_failures",
    focus_range=FocusRange(Closed(0), Open(10)),
    segments=["shelly_consecutive_failures"],
)

perfometer_shelly_connectivity = Perfometer(
    name="shelly_connectivity",
    focus_range=FocusRange(Closed(0), Closed(3)),
    segments=[
        "shelly_bluetooth_enabled",
        "shelly_mqtt_connected",
        "shelly_cloud_connected",
    ],
)

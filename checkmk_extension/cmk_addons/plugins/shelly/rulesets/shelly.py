# Copied into the OMD site at:
#   ~/local/lib/python3/cmk_addons/plugins/shelly/rulesets/shelly.py
#
# One rule: the list of Shelly devices to poll. Each entry's alias becomes
# the piggyback hostname the special agent reports data under.

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Float,
    InputHint,
    Integer,
    LevelDirection,
    LevelsType,
    List,
    Password,
    SimpleLevels,
    SimpleLevelsConfigModel,
    SingleChoice,
    SingleChoiceElement,
    String,
    migrate_to_float_simple_levels,
    migrate_to_password,
    validators,
)
from cmk.rulesets.v1.rule_specs import (
    CheckParameters,
    HostCondition,
    SpecialAgent,
    Topic,
)


def _device_form() -> Dictionary:
    return Dictionary(
        elements={
            "alias": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("Alias"),
                    help_text=Help(
                        "Used as the piggyback hostname this device's data is reported under."
                    ),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "host": DictElement(
                required=True,
                parameter_form=String(
                    title=Title("IP address or hostname"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
            ),
            "username": DictElement(
                parameter_form=String(
                    title=Title("Username"),
                ),
            ),
            "password": DictElement(
                parameter_form=Password(
                    title=Title("Password"),
                    migrate=migrate_to_password,
                ),
            ),
            "timeout": DictElement(
                required=True,
                parameter_form=Float(
                    title=Title("Timeout"),
                    help_text=Help(
                        "How long to wait for this device to respond, in seconds."
                    ),
                    prefill=DefaultValue(10.0),
                    custom_validate=(validators.NumberInRange(min_value=0.1),),
                ),
            ),
        },
    )


def _special_agent_form() -> Dictionary:
    return Dictionary(
        elements={
            "devices": DictElement(
                required=True,
                parameter_form=List(
                    title=Title("Shelly devices"),
                    element_template=_device_form(),
                    add_element_label=Label("Add device"),
                ),
            ),
        },
    )


rule_spec_special_agent_shelly = SpecialAgent(
    name="shelly",
    title=Title("Shelly devices"),
    topic=Topic.APPLICATIONS,
    parameter_form=_special_agent_form,
)


def _reachability_parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "failures_before_crit": DictElement(
                required=True,
                parameter_form=Integer(
                    title=Title("Consecutive failed checks before CRIT"),
                    help_text=Help(
                        "Below this many consecutive failed checks in a row, an "
                        "unreachable device is only WARN, not CRIT."
                    ),
                    prefill=DefaultValue(3),
                    custom_validate=(validators.NumberInRange(min_value=1),),
                ),
            ),
        }
    )


def _expectation_field(title: Title) -> SingleChoice:
    return SingleChoice(
        title=title,
        elements=[
            SingleChoiceElement("enabled", Title("Expect enabled")),
            SingleChoiceElement("disabled", Title("Expect disabled")),
            SingleChoiceElement("ignore", Title("Ignore")),
        ],
        prefill=DefaultValue("ignore"),
    )


def _connectivity_parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "bluetooth": DictElement(
                required=True,
                parameter_form=_expectation_field(Title("Bluetooth")),
            ),
            "mqtt": DictElement(
                required=True,
                parameter_form=_expectation_field(Title("MQTT")),
            ),
            "cloud": DictElement(
                required=True,
                parameter_form=_expectation_field(Title("Cloud")),
            ),
            "websocket": DictElement(
                required=True,
                parameter_form=_expectation_field(Title("Websocket")),
            ),
        }
    )


def _severity_field(title: Title, default: str) -> SingleChoice:
    return SingleChoice(
        title=title,
        elements=[
            SingleChoiceElement("ignore", Title("Ignore")),
            SingleChoiceElement("warn", Title("WARN")),
            SingleChoiceElement("crit", Title("CRIT")),
        ],
        prefill=DefaultValue(default),
    )


def _info_parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "temperature": DictElement[SimpleLevelsConfigModel[float]](
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels for temperature"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_levels_type=DefaultValue(LevelsType.FIXED),
                    prefill_fixed_levels=InputHint((70.0, 80.0)),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "wifi_signal": DictElement[SimpleLevelsConfigModel[float]](
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Lower levels for WiFi signal strength"),
                    help_text=Help(
                        "In dBm. Less negative is stronger, so these are levels "
                        "below which the signal is considered too weak."
                    ),
                    level_direction=LevelDirection.LOWER,
                    form_spec_template=Float(),
                    prefill_levels_type=DefaultValue(LevelsType.FIXED),
                    prefill_fixed_levels=InputHint((-70.0, -80.0)),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "unset_password": DictElement(
                required=True,
                parameter_form=_severity_field(
                    Title("If the device has no password set"), "ignore"
                ),
            ),
            "restart_required": DictElement(
                required=True,
                parameter_form=_severity_field(
                    Title("If the device requires a restart"), "warn"
                ),
            ),
            "firmware_update_available": DictElement(
                required=True,
                parameter_form=_severity_field(
                    Title("If a firmware update is available"), "warn"
                ),
            ),
            "unexpected_reboot": DictElement(
                required=True,
                parameter_form=_severity_field(
                    Title(
                        "If the last reboot was unexpected (crash, watchdog, brownout)"
                    ),
                    "warn",
                ),
            ),
        }
    )


def _switch_parameter_form() -> Dictionary:
    return Dictionary(
        elements={
            "power": DictElement[SimpleLevelsConfigModel[float]](
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels for power"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_levels_type=DefaultValue(LevelsType.FIXED),
                    prefill_fixed_levels=InputHint((2000.0, 2500.0)),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "current": DictElement[SimpleLevelsConfigModel[float]](
                required=True,
                parameter_form=SimpleLevels(
                    title=Title("Upper levels for current"),
                    level_direction=LevelDirection.UPPER,
                    form_spec_template=Float(),
                    prefill_levels_type=DefaultValue(LevelsType.FIXED),
                    prefill_fixed_levels=InputHint((10.0, 13.0)),
                    migrate=migrate_to_float_simple_levels,
                ),
            ),
            "missing_auto_off_timer": DictElement(
                required=True,
                parameter_form=_severity_field(
                    Title("If no auto-off timer is configured on the relay"),
                    "ignore",
                ),
            ),
        }
    )


def _gen2_settings_form() -> Dictionary:
    return Dictionary(
        elements={
            "reachability": DictElement(
                required=True,
                parameter_form=_reachability_parameter_form(),
            ),
            "connectivity": DictElement(
                required=True,
                parameter_form=_connectivity_parameter_form(),
            ),
            "info": DictElement(
                required=True,
                parameter_form=_info_parameter_form(),
            ),
            "switch": DictElement(
                required=True,
                parameter_form=_switch_parameter_form(),
            ),
        }
    )


rule_spec_shelly_gen2_settings = CheckParameters(
    name="shelly_gen2_settings",
    topic=Topic.APPLICATIONS,
    parameter_form=_gen2_settings_form,
    title=Title("Shelly Gen2 settings"),
    condition=HostCondition(),
)

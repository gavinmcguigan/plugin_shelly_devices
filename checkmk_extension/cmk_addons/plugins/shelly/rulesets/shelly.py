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
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, SpecialAgent, Topic


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


rule_spec_shelly_reachability = CheckParameters(
    name="shelly_reachability",
    topic=Topic.APPLICATIONS,
    parameter_form=_reachability_parameter_form,
    title=Title("Shelly reachability thresholds"),
    condition=HostCondition(),
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
        }
    )


rule_spec_shelly_connectivity = CheckParameters(
    name="shelly_connectivity",
    topic=Topic.APPLICATIONS,
    parameter_form=_connectivity_parameter_form,
    title=Title("Shelly connectivity expectations"),
    condition=HostCondition(),
)


def _switch_parameter_form() -> Dictionary:
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
        }
    )


rule_spec_shelly_switch = CheckParameters(
    name="shelly_switch",
    topic=Topic.APPLICATIONS,
    parameter_form=_switch_parameter_form,
    title=Title("Shelly switch temperature levels"),
    condition=HostCondition(),
)

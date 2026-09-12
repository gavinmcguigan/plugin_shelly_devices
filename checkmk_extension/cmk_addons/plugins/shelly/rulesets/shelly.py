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
    Integer,
    List,
    Password,
    String,
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

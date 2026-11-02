import pytest

from maclolbins.views import entitlement_info


@pytest.mark.parametrize(
    "key", ["com.apple.private.tcc.allow", "com.apple.private.tcc.allow.overridable"]
)
def test_grant_keys_name_their_tcc_services(key):
    info = entitlement_info(key, ["kTCCServiceSystemPolicyAllFiles"])
    assert info["tcc_services"] == [
        {"service": "kTCCServiceSystemPolicyAllFiles", "label": "Full Disk Access"}
    ]


@pytest.mark.parametrize(
    "key",
    [
        "com.apple.private.tcc.allow-prompting",
        "com.apple.private.tcc.manager.access.delete",
        "com.apple.private.tcc.check-allow-on-responsible-process",
    ],
)
def test_non_grant_tcc_keys_list_no_services(key):
    assert entitlement_info(key, ["kTCCServiceAll"])["tcc_services"] == []


def test_grant_key_with_non_list_value_lists_no_services():
    assert entitlement_info("com.apple.private.tcc.allow", True)["tcc_services"] == []

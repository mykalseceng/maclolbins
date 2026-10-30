from maclolbins.entitlements import explain


def test_documented_key_links_to_apple():
    info = explain("com.apple.security.network.client")
    assert info.documented is True
    assert info.url.startswith(
        "https://developer.apple.com/documentation/bundleresources/entitlements/"
    )
    assert info.summary


def test_documented_lookup_is_case_insensitive():
    lower = explain("com.apple.security.cs.disable-library-validation")
    mixed = explain("com.apple.Security.CS.Disable-Library-Validation")
    assert lower.documented
    assert mixed.documented
    assert lower.url == mixed.url


def test_undocumented_key_has_no_offsite_link():
    info = explain("com.apple.private.tcc.allow")
    assert info.documented is False
    assert info.url == ""
    assert info.namespace == "Private TCC"


def test_namespace_is_assigned_by_prefix():
    assert explain("com.apple.rootless.volume.Preboot").namespace == "SIP (rootless)"
    assert explain("com.apple.security.cs.allow-jit").namespace == "Hardened runtime"
    assert explain("task_for_pid-allow").namespace == "Other"

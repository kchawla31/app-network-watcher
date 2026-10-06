/// Trusts this tool's user CA in debug and release builds of an app you ship.
pub fn release_network_security_config() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"#
}

/// Trusts the user CA only while the app is debuggable.
pub fn debug_only_network_security_config() -> &'static str {
    r#"<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"#
}

pub fn manifest_attribute() -> &'static str {
    r#"android:networkSecurityConfig="@xml/network_security_config""#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_config_trusts_user_cas_for_every_build_type() {
        let xml = release_network_security_config();
        assert!(xml.contains("<base-config"));
        assert!(xml.contains("src=\"user\""));
        assert!(!xml.contains("debug-overrides"));
        assert!(debug_only_network_security_config().contains("<debug-overrides"));
    }
}

"""Name TCC (Transparency, Consent and Control) services the way System Settings does.

TCC records consent per service, keyed by an internal identifier such as
kTCCServiceSystemPolicyAllFiles. The same identifiers appear in TCC.db grants and in the values
of com.apple.private.tcc.allow entitlements, so one table serves both.
"""

FULL_DISK_ACCESS = "kTCCServiceSystemPolicyAllFiles"
AUTOMATION = "kTCCServiceAppleEvents"

SERVICE_LABELS: dict[str, str] = {
    "kTCCServiceAll": "Every TCC service",
    FULL_DISK_ACCESS: "Full Disk Access",
    AUTOMATION: "Automation",
    "kTCCServiceAccessibility": "Accessibility",
    "kTCCServicePostEvent": "Posting input events",
    "kTCCServiceListenEvent": "Input Monitoring",
    "kTCCServiceScreenCapture": "Screen Recording",
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServiceCalendar": "Calendars",
    "kTCCServiceReminders": "Reminders",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceMediaLibrary": "Media & Apple Music",
    "kTCCServiceSystemPolicyDesktopFolder": "Desktop folder",
    "kTCCServiceSystemPolicyDocumentsFolder": "Documents folder",
    "kTCCServiceSystemPolicyDownloadsFolder": "Downloads folder",
    "kTCCServiceSystemPolicyNetworkVolumes": "Network volumes",
    "kTCCServiceSystemPolicyRemovableVolumes": "Removable volumes",
    "kTCCServiceSystemPolicySysAdminFiles": "Administrator files",
    "kTCCServiceSystemPolicyAppBundles": "App Management",
    "kTCCServiceSystemPolicyAppData": "Other apps' data",
    "kTCCServiceDeveloperTool": "Developer Tools",
    "kTCCServiceEndpointSecurityClient": "Endpoint Security client",
    "kTCCServiceUbiquity": "iCloud Drive",
    "kTCCServiceLiverpool": "iCloud (CloudKit)",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceLocation": "Location Services",
}


def service_label(service: str) -> str:
    """Return the System Settings name for a TCC service, or the identifier if unknown."""
    return SERVICE_LABELS.get(service, service)

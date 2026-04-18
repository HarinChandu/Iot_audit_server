from html import escape

from audit_execution import build_requirement_assessment, render_requirement_assessment, run_requirement_hooks

V4_REQUIREMENTS = [
    {
        "id": "4.1.1",
        "area": "General",
        "title": "Secure channels",
        "requirement": "Verify that communication occurs over a secure channel with confidentiality and integrity.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access",
        "tools": "Wireshark, TestSSL.sh",
        "evidence": "Channel security",
        "auto_hooks": [{"name": "tshark"}, {"name": "testssl"}],
        "steps": [
            "Capture common traffic with Wireshark or tcpdump.",
            "Verify TLS with TestSSL.sh on exposed services.",
            "Test replay behavior where relevant.",
            "Report insecure channels with packet captures.",
        ],
    },
    {
        "id": "4.1.2",
        "area": "General",
        "title": "TLS configuration",
        "requirement": "Verify that only strong TLS cipher suites are enabled.",
        "assessment": "TLS scanning",
        "artifacts": "Device IP",
        "tools": "TestSSL.sh, SSLyze",
        "evidence": "Cipher suite strength",
        "auto_hooks": [{"name": "testssl"}, {"name": "openssl"}],
        "steps": [
            "Scan TLS with TestSSL.sh.",
            "Verify strong cipher suites such as AES-256-GCM.",
            "Test for weak ciphers with OpenSSL or SSLyze.",
            "Report weak ciphers with scan results.",
        ],
    },
    {
        "id": "4.1.3",
        "area": "General",
        "title": "Certificate verification",
        "requirement": "Verify that the device verifies X.509 certificates in TLS.",
        "assessment": "TLS testing",
        "artifacts": "Device IP",
        "tools": "OpenSSL, Wireshark",
        "evidence": "Certificate validation",
        "auto_hooks": [{"name": "openssl"}, {"name": "tshark"}],
        "steps": [
            "Test TLS with invalid certificates using OpenSSL.",
            "Verify rejection behavior with Wireshark.",
            "Test certificate chain validation.",
            "Report bypasses with packet captures.",
        ],
    },
    {
        "id": "4.2.1",
        "area": "Machine-to-Machine",
        "title": "Data sensitivity",
        "requirement": "Verify that unencrypted communication is limited to non-sensitive data.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access, command set carrying sensitive data",
        "tools": "Wireshark",
        "evidence": "Unencrypted sensitive data",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Capture traffic with Wireshark.",
            "Identify commands that carry sensitive data as per OEM docs.",
            "Check whether sensitive data is encrypted.",
            "Report unencrypted sensitive data with packet captures.",
        ],
    },
    {
        "id": "4.2.2",
        "area": "Machine-to-Machine",
        "title": "MQTT access controls",
        "requirement": "Verify that MQTT brokers only allow authorized devices.",
        "assessment": "Auth testing",
        "artifacts": "MQTT broker access and auth protocol",
        "tools": "Mosquitto, Burp Suite",
        "evidence": "Access violations",
        "steps": [
            "Send requests as an unauthorized device and observe broker behavior.",
            "Verify restrictions with Burp Suite if an HTTP control plane exists.",
            "Attempt unauthorized publish and subscribe actions.",
            "Report bypasses with MQTT logs.",
        ],
    },
    {
        "id": "4.2.3",
        "area": "Machine-to-Machine",
        "title": "MQTT auth",
        "requirement": "Verify that certificates are favored over username and password for MQTT.",
        "assessment": "Auth testing",
        "artifacts": "MQTT broker",
        "tools": "Mosquitto, OpenSSL",
        "evidence": "Certificate usage",
        "steps": [
            "Test MQTT authentication with Mosquitto clients.",
            "Verify certificate usage with OpenSSL-backed checks where applicable.",
            "Check whether password-only auth is accepted.",
            "Report non-certificate authentication flows with logs.",
        ],
    },
    {
        "id": "4.3.1",
        "area": "Bluetooth",
        "title": "Pairing controls",
        "requirement": "Verify that pairing and discovery is blocked except when necessary.",
        "assessment": "Bluetooth testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "hcitool, BlueZ",
        "evidence": "Pairing controls",
        "steps": [
            "Scan with hcitool to determine whether Bluetooth is discoverable when it should not be.",
            "Test pairing with BlueZ.",
            "Verify pairing only works inside the intended pairing mode.",
            "Report weak pairing or discoverability with scan logs.",
        ],
    },
    {
        "id": "4.3.2",
        "area": "Bluetooth",
        "title": "PIN strength",
        "requirement": "Verify that PIN or PassKey codes are not easily guessable.",
        "assessment": "Brute-force testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "BlueZ, custom scripts",
        "evidence": "PIN vulnerabilities",
        "steps": [
            "Attempt PIN guessing with BlueZ.",
            "Test common PINs such as 0000.",
            "Verify complexity requirements.",
            "Report weak PINs with test results.",
        ],
    },
    {
        "id": "4.3.3",
        "area": "Bluetooth",
        "title": "Bluetooth pairing",
        "requirement": "Verify that old Bluetooth versions require a PIN for pairing.",
        "assessment": "Protocol testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "BlueZ",
        "evidence": "PIN enforcement",
        "steps": [
            "Test pairing behavior with legacy Bluetooth modes.",
            "Verify the PIN requirement.",
            "Attempt pairing without a PIN.",
            "Report pairing issues with logs.",
        ],
    },
    {
        "id": "4.3.4",
        "area": "Bluetooth",
        "title": "SSP authentication",
        "requirement": "Verify that modern Bluetooth requires 6-digit SSP authentication.",
        "assessment": "Pairing testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "BlueZ",
        "evidence": "SSP compliance",
        "steps": [
            "Test SSP pairing with BlueZ.",
            "Verify the 6-digit requirement.",
            "Test for insecure pairing modes such as Just Works.",
            "Report non-compliant modes with logs.",
        ],
    },
    {
        "id": "4.3.5",
        "area": "Bluetooth",
        "title": "Key strength",
        "requirement": "Verify that encryption keys are the maximum size supported.",
        "assessment": "Key analysis",
        "artifacts": "Device, Bluetooth traffic",
        "tools": "Wireshark, BlueZ",
        "evidence": "Key size",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Capture Bluetooth traffic with Wireshark.",
            "Analyze key size with BlueZ.",
            "Verify against device specifications.",
            "Report weak keys with packet captures.",
        ],
    },
    {
        "id": "4.3.6",
        "area": "Bluetooth",
        "title": "Pairing method",
        "requirement": "Verify that the most secure Bluetooth pairing method is used.",
        "assessment": "Protocol testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "BlueZ",
        "evidence": "Pairing method",
        "steps": [
            "Test pairing methods with BlueZ.",
            "Verify the strongest supported method is used.",
            "Report insecure pairing methods with logs.",
        ],
    },
    {
        "id": "4.3.7",
        "area": "Bluetooth",
        "title": "Security mode",
        "requirement": "Verify that the strongest Bluetooth Security Mode and Level is used.",
        "assessment": "Protocol testing",
        "artifacts": "Device, Bluetooth adapter",
        "tools": "BlueZ",
        "evidence": "Mode compliance",
        "steps": [
            "Test security modes with BlueZ.",
            "Verify Mode 4, Level 4 for Bluetooth 4.1 and above where applicable.",
            "Report weak modes with logs.",
        ],
    },
    {
        "id": "4.4.1",
        "area": "Wi-Fi",
        "title": "Wi-Fi status",
        "requirement": "Verify that Wi-Fi connectivity is disabled unless required.",
        "assessment": "Device testing",
        "artifacts": "Device",
        "tools": "iwconfig, Nmap",
        "evidence": "Wi-Fi usage",
        "auto_hooks": [{"name": "nmap"}],
        "steps": [
            "Check Wi-Fi status with iwconfig.",
            "Scan with Nmap for Wi-Fi interfaces or related exposure.",
            "Verify necessity against device documentation.",
            "Report enabled Wi-Fi with scan results.",
        ],
    },
    {
        "id": "4.4.2",
        "area": "Wi-Fi",
        "title": "Wi-Fi security",
        "requirement": "Verify that WPA2 or higher is used for Wi-Fi communications.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access",
        "tools": "Wireshark, aircrack-ng",
        "evidence": "Security protocol",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Capture Wi-Fi traffic with Wireshark.",
            "Verify WPA2 or stronger protection with aircrack-ng.",
            "Test for weaker protocols such as WPA or WEP.",
            "Report weak protocols with packet captures.",
        ],
    },
    {
        "id": "4.4.3",
        "area": "Wi-Fi",
        "title": "Wi-Fi encryption",
        "requirement": "Verify that WPA uses AES encryption in CCMP mode.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access",
        "tools": "Wireshark, aircrack-ng",
        "evidence": "Encryption mode",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Capture Wi-Fi traffic with Wireshark.",
            "Verify CCMP with aircrack-ng.",
            "Test for TKIP or other non-AES modes.",
            "Report non-AES modes with packet captures.",
        ],
    },
    {
        "id": "4.4.4",
        "area": "Wi-Fi",
        "title": "WPS status",
        "requirement": "Verify that Wi-Fi Protected Setup (WPS) is not used.",
        "assessment": "Device testing",
        "artifacts": "Device",
        "tools": "reaver, Wireshark",
        "evidence": "WPS usage",
        "steps": [
            "Test WPS with reaver.",
            "Verify absence of WPS behavior with Wireshark.",
            "Report enabled WPS with test results.",
        ],
    },
]


def _render_row(item, hook_results):
    assessment = build_requirement_assessment(item, hook_results)
    return f"""
    <tr>
        <td>{escape(item["id"])}</td>
        <td>{escape(item["title"])}</td>
        <td>{render_requirement_assessment(assessment)}</td>
    </tr>
    """


def run_v4(args, selected_checks=None, log_callback=None):
    selected_set = set(selected_checks or [])
    requirements = V4_REQUIREMENTS

    if selected_set:
        requirements = [item for item in V4_REQUIREMENTS if item["id"] in selected_set]

    rows = "".join(
        _render_row(item, run_requirement_hooks(item, args, log_callback=log_callback))
        for item in requirements
    )
    target_ip = escape(args.get("ip", "N/A"))
    selected_label = "Full 4.x.x section"

    if selected_set:
        selected_label = ", ".join(item["id"] for item in requirements)

    return f"""
    <section>
        <style>
            .v4-summary {{
                margin: 16px 0 24px;
                padding: 16px;
                border-radius: 12px;
                background: #f8fafc;
                border: 1px solid #dbe4f0;
            }}
            .v4-table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
            }}
            .v4-table th, .v4-table td {{
                border: 1px solid #cbd5e1;
                padding: 10px;
                vertical-align: top;
                text-align: left;
            }}
            .v4-table th {{
                background: #0f172a;
                color: #ffffff;
            }}
            .v4-table tr:nth-child(even) {{
                background: #f8fafc;
            }}
            .status-chip {{
                display: inline-block;
                margin-bottom: 8px;
                padding: 4px 8px;
                border-radius: 999px;
                background: #fef3c7;
                color: #92400e;
                font-weight: 600;
            }}
            .requirement-assessment ul {{
                margin: 6px 0 0;
                padding-left: 18px;
            }}
            .assessment-block + .assessment-block {{
                margin-top: 10px;
            }}
            .verdict-pill {{
                display: inline-block;
                margin-bottom: 10px;
                padding: 4px 10px;
                border-radius: 999px;
                font-weight: 700;
                font-size: 12px;
            }}
            .verdict-pass {{
                background: #dcfce7;
                color: #166534;
            }}
            .verdict-fail {{
                background: #fee2e2;
                color: #991b1b;
            }}
            .verdict-review {{
                background: #fef3c7;
                color: #92400e;
            }}
        </style>

        <h2>Section 4.x.x - V4 Communication Requirements</h2>

        <div class="v4-summary">
            <p><strong>Audit target:</strong> {target_ip}</p>
            <p><strong>Selected controls:</strong> {escape(selected_label)}</p>
            <p><strong>Coverage:</strong> General Communication, Machine-to-Machine, Bluetooth, and Wi-Fi.</p>
            <p><strong>Current mode:</strong> Requirement-driven checklist with live tool hooks where the server environment and inputs support them.</p>
        </div>

        <table class="v4-table">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Title of Checklist</th>
                    <th>Status and Failure Details</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </section>
    """

from html import escape

from audit_execution import build_requirement_assessment, render_requirement_assessment, run_requirement_hooks

V3_REQUIREMENTS = [
    {
        "id": "3.2.1",
        "area": "OS Configuration",
        "title": "OS configuration",
        "requirement": "Verify that the embedded OS is configured per industry best practices.",
        "assessment": "Config analysis",
        "artifacts": "Device, firmware",
        "tools": "Lynis, Ghidra",
        "evidence": "Config compliance",
        "auto_hooks": [{"name": "lynis"}],
        "steps": [
            "Run Lynis audit for OS configuration checks.",
            "Analyze kernel and OS configuration paths in Ghidra.",
            "Compare findings with CIS-style benchmarks.",
            "Report non-compliant configuration findings with Lynis output.",
        ],
    },
    {
        "id": "3.2.2",
        "area": "OS Configuration",
        "title": "Network services",
        "requirement": "Verify that only necessary network services are exposed.",
        "assessment": "Network scanning",
        "artifacts": "Device, network access, OEM service documentation",
        "tools": "Nmap",
        "evidence": "Unnecessary services",
        "auto_hooks": [{"name": "nmap"}],
        "steps": [
            "Scan the device with Nmap.",
            "Identify exposed services and open ports.",
            "Verify necessity against OEM documentation.",
            "Report unnecessary services with scan results.",
        ],
    },
    {
        "id": "3.2.3",
        "area": "OS Configuration",
        "title": "Protocol usage",
        "requirement": "Verify that legacy or insecure protocols such as Telnet and FTP are not used.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access",
        "tools": "Wireshark, Nmap",
        "evidence": "Insecure protocols",
        "auto_hooks": [{"name": "nmap"}, {"name": "tshark"}],
        "steps": [
            "Identify active ports from Nmap.",
            "Attempt to probe ports with insecure protocol commands.",
            "Capture traffic with Wireshark for Telnet or FTP patterns.",
            "Report insecure protocol usage with packet captures.",
        ],
    },
    {
        "id": "3.2.4",
        "area": "OS Configuration",
        "title": "Known vulnerabilities",
        "requirement": "Verify that OS kernel and software components are up to date.",
        "assessment": "Vulnerability scanning",
        "artifacts": "Firmware, device",
        "tools": "cve-bin-tool, Lynis",
        "evidence": "Known vulnerabilities",
        "auto_hooks": [{"name": "binwalk"}, {"name": "cve_bin_tool"}],
        "steps": [
            "Extract the firmware with Binwalk.",
            "Determine kernel and component versions from the firmware.",
            "Run cve-bin-tool for component CVEs.",
            "Report outdated components with CVE details.",
        ],
    },
    {
        "id": "3.4.2",
        "area": "Software Updates",
        "title": "Auto-update process",
        "requirement": "Verify that devices can be updated automatically on a schedule.",
        "assessment": "Process testing",
        "artifacts": "OEM config file, device, update server",
        "tools": "Postman",
        "evidence": "Auto-update functionality",
        "steps": [
            "Check the update schedule in the device configuration.",
            "Trigger an update using Postman if applicable.",
            "Verify update execution.",
            "Report failures with API logs.",
        ],
    },
    {
        "id": "3.4.3",
        "area": "Software Updates",
        "title": "Update signing",
        "requirement": "Verify that updates are cryptographically signed by a trusted source.",
        "assessment": "Signature verification",
        "artifacts": "Update binary",
        "tools": "OpenSSL, Ghidra",
        "evidence": "Signature integrity",
        "auto_hooks": [{"name": "openssl"}, {"name": "ghidra_strings"}],
        "steps": [
            "Confirm the update binary is present.",
            "Verify the signature with OpenSSL.",
            "Inspect signature verification code paths if needed.",
            "Report missing or invalid signatures with verification logs.",
        ],
    },
    {
        "id": "3.4.4",
        "area": "Software Updates",
        "title": "Update process",
        "requirement": "Verify that the update process is not vulnerable to TOCTOU attacks.",
        "assessment": "Race condition testing",
        "artifacts": "Update binary",
        "tools": "Custom scripts, Ghidra",
        "evidence": "TOCTOU vulnerabilities",
        "steps": [
            "Analyze update code flow with Ghidra.",
            "Test race conditions with custom scripts.",
            "Verify immediate application post-check.",
            "Report vulnerabilities with script outputs.",
        ],
    },
    {
        "id": "3.4.5",
        "area": "Software Updates",
        "title": "Update behavior",
        "requirement": "Verify that updates do not modify user settings without notification.",
        "assessment": "Functional testing",
        "artifacts": "Device, test settings",
        "tools": "Custom scripts",
        "evidence": "Setting preservation",
        "steps": [
            "Apply an update to the device.",
            "Check user settings before and after the update.",
            "Verify a user notification is present if settings change.",
            "Report unauthorized changes with settings logs.",
        ],
    },
    {
        "id": "3.4.7",
        "area": "Software Updates",
        "title": "Update failure handling",
        "requirement": "Verify that in case of update failure, the device reverts to a backup image or notifies.",
        "assessment": "Update testing",
        "artifacts": "Device, update binary, device storage path",
        "tools": "Postman, Wireshark",
        "evidence": "Failure handling",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Simulate an update failure with a corrupted binary or blocked transfer.",
            "Verify rollback or user notification behavior.",
            "Check backup image integrity.",
            "Report failures with logs and captures.",
        ],
    },
    {
        "id": "3.4.8",
        "area": "Software Updates",
        "title": "Firmware flashing",
        "requirement": "Verify that unsigned debug or pre-production firmware cannot be flashed.",
        "assessment": "Flash testing",
        "artifacts": "Debug firmware",
        "tools": "JTAG, OpenSSL",
        "evidence": "Firmware flashing protection",
        "steps": [
            "Attempt to flash unsigned debug firmware.",
            "Verify signature enforcement with OpenSSL-backed validation if available.",
            "Confirm the flash is rejected.",
            "Report any successful unauthorized flash attempt with device logs.",
        ],
    },
    {
        "id": "3.4.10",
        "area": "Software Updates",
        "title": "Server authentication",
        "requirement": "Verify that the device authenticates to the update server before downloading.",
        "assessment": "Network analysis",
        "artifacts": "Device, update server, auth process",
        "tools": "Wireshark, Postman",
        "evidence": "Auth effectiveness",
        "auto_hooks": [{"name": "tshark"}],
        "steps": [
            "Capture update traffic with Wireshark to identify protocol and port.",
            "Use captured flow details to verify authentication with Postman where applicable.",
            "Test behavior when server authentication fails.",
            "Report weak authentication with packet captures.",
        ],
    },
    {
        "id": "3.4.12",
        "area": "Software Updates",
        "title": "Update transmission",
        "requirement": "Verify that updates are transmitted using an encrypted channel.",
        "assessment": "Network analysis",
        "artifacts": "Device, network access",
        "tools": "Wireshark, TestSSL.sh",
        "evidence": "Channel security",
        "auto_hooks": [{"name": "tshark"}, {"name": "testssl"}],
        "steps": [
            "Capture update traffic with Wireshark.",
            "Verify TLS with TestSSL.sh against the update server.",
            "Test for plaintext transport.",
            "Report insecure channels with packet captures.",
        ],
    },
    {
        "id": "3.6.2",
        "area": "Kernel Space Application Requirements",
        "title": "Module usage",
        "requirement": "Verify that only required kernel modules are enabled.",
        "assessment": "Kernel analysis",
        "artifacts": "Device, firmware, OEM whitelist of allowed modules",
        "tools": "lsmod, Ghidra",
        "evidence": "Unnecessary modules",
        "steps": [
            "List loaded modules with lsmod.",
            "Compare enabled modules against the OEM-approved list.",
            "Analyze suspicious module references in firmware if needed.",
            "Report unnecessary modules with lsmod output.",
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


def run_v3(args, selected_checks=None, log_callback=None):
    selected_set = set(selected_checks or [])
    requirements = V3_REQUIREMENTS

    if selected_set:
        requirements = [item for item in V3_REQUIREMENTS if item["id"] in selected_set]

    rows = "".join(
        _render_row(item, run_requirement_hooks(item, args, log_callback=log_callback))
        for item in requirements
    )
    target_ip = escape(args.get("ip", "N/A"))
    selected_label = "Full 3.x.x section"

    if selected_set:
        selected_label = ", ".join(item["id"] for item in requirements)

    return f"""
    <section>
        <style>
            .v3-summary {{
                margin: 16px 0 24px;
                padding: 16px;
                border-radius: 12px;
                background: #f8fafc;
                border: 1px solid #dbe4f0;
            }}
            .v3-table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 13px;
            }}
            .v3-table th, .v3-table td {{
                border: 1px solid #cbd5e1;
                padding: 10px;
                vertical-align: top;
                text-align: left;
            }}
            .v3-table th {{
                background: #0f172a;
                color: #ffffff;
            }}
            .v3-table tr:nth-child(even) {{
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

        <h2>Section 3.x.x - V3 Software Platform Requirements</h2>

        <div class="v3-summary">
            <p><strong>Audit target:</strong> {target_ip}</p>
            <p><strong>Selected controls:</strong> {escape(selected_label)}</p>
            <p><strong>Coverage:</strong> OS Configuration, Software Updates, and Kernel Space Application Requirements.</p>
            <p><strong>Current mode:</strong> Requirement-driven checklist with live tool hooks where the server environment and inputs support them.</p>
        </div>

        <table class="v3-table">
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
      

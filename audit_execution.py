import html
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path


def _safe_name(value):
    return "".join(char if char.isalnum() or char in {"-", "_", "."} else "_" for char in value)


def tool_exists(tool_name):
    return shutil.which(tool_name) is not None


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def write_text(path, content):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def run_command(command, output_path, timeout=120, cwd=None):
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        output = []
        output.append(f"$ {' '.join(shlex.quote(part) for part in command)}")
        output.append("")
        output.append("STDOUT:")
        output.append(completed.stdout or "<empty>")
        output.append("")
        output.append("STDERR:")
        output.append(completed.stderr or "<empty>")
        output.append("")
        output.append(f"Exit code: {completed.returncode}")
        write_text(output_path, "\n".join(output))
        return {
            "status": "ok" if completed.returncode == 0 else "warning",
            "message": f"Command finished with exit code {completed.returncode}",
            "output_path": output_path,
        }
    except FileNotFoundError:
        write_text(output_path, "Tool not found in PATH.\n")
        return {
            "status": "skipped",
            "message": "Tool not found in PATH",
            "output_path": output_path,
        }
    except subprocess.TimeoutExpired:
        write_text(output_path, "Command timed out.\n")
        return {
            "status": "warning",
            "message": "Command timed out",
            "output_path": output_path,
        }


def _result(status, message, output_path=None):
    return {"status": status, "message": message, "output_path": output_path}


def run_nmap_scan(check_id, args):
    target = args.get("ip")
    if not target:
        return _result("skipped", "No target IP provided")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_nmap.txt")
    return run_command(["nmap", "-sV", target], output_path, timeout=180)


def run_openssl_probe(check_id, args):
    target = args.get("ip")
    port = args.get("tls_port", "443")
    if not target:
        return _result("skipped", "No target IP provided")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_openssl.txt")
    return run_command(
        ["openssl", "s_client", "-connect", f"{target}:{port}", "-servername", target],
        output_path,
        timeout=120,
    )


def run_testssl_scan(check_id, args):
    target = args.get("ip")
    port = args.get("tls_port", "443")
    if not target:
        return _result("skipped", "No target IP provided")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_testssl.txt")
    return run_command(["testssl.sh", f"{target}:{port}"], output_path, timeout=300)


def run_lynis_audit(check_id, args):
    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_lynis.txt")
    return run_command(["lynis", "audit", "system", "--quick"], output_path, timeout=600)


def run_binwalk_scan(check_id, args):
    firmware_path = args.get("firmware_path")
    if not firmware_path:
        return _result("skipped", "No firmware path provided")
    if not os.path.exists(firmware_path):
        return _result("skipped", f"Firmware path not found: {firmware_path}")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_binwalk.txt")
    return run_command(["binwalk", firmware_path], output_path, timeout=300)


def run_cve_bin_tool(check_id, args):
    firmware_path = args.get("firmware_path")
    if not firmware_path:
        return _result("skipped", "No firmware path provided")
    if not os.path.exists(firmware_path):
        return _result("skipped", f"Firmware path not found: {firmware_path}")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_cve_bin_tool.txt")
    return run_command(["cve-bin-tool", firmware_path], output_path, timeout=600)


def run_tshark_capture(check_id, args):
    interface = args.get("network_interface")
    duration = args.get("capture_seconds", "10")
    if not interface:
        return _result("skipped", "No network interface provided")

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_tshark.txt")
    return run_command(
        ["tshark", "-i", interface, "-a", f"duration:{duration}"],
        output_path,
        timeout=int(duration) + 30,
    )


def run_ghidra_strings(check_id, args):
    firmware_path = args.get("firmware_path")
    if not firmware_path:
        return _result("skipped", "No firmware path provided")
    if not os.path.exists(firmware_path):
        return _result("skipped", f"Firmware path not found: {firmware_path}")

    strings_tool = shutil.which("strings")
    if not strings_tool:
        output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_ghidra_stub.txt")
        write_text(output_path, "Ghidra headless integration not configured and `strings` is unavailable.\n")
        return _result("skipped", "Ghidra headless integration not configured", output_path)

    output_path = os.path.join(args["outdir"], "tool_outputs", f"{_safe_name(check_id)}_strings.txt")
    return run_command([strings_tool, "-a", firmware_path], output_path, timeout=300)


def run_command_from_hook(hook, check_id, args):
    hook_name = hook["name"]
    hook_map = {
        "nmap": run_nmap_scan,
        "openssl": run_openssl_probe,
        "testssl": run_testssl_scan,
        "lynis": run_lynis_audit,
        "binwalk": run_binwalk_scan,
        "cve_bin_tool": run_cve_bin_tool,
        "tshark": run_tshark_capture,
        "ghidra_strings": run_ghidra_strings,
    }
    return hook_map[hook_name](check_id, args)


def run_requirement_hooks(requirement, args, log_callback=None):
    hook_results = []

    for hook in requirement.get("auto_hooks", []):
        tool_label = hook["name"]
        if log_callback:
            log_callback(f"{requirement['id']}: running {tool_label}")
        result = run_command_from_hook(hook, requirement["id"], args)
        result["tool"] = tool_label
        hook_results.append(result)

    return hook_results


def render_hook_results(hook_results):
    if not hook_results:
        return '<div class="status-chip">Manual review required</div>'

    items = []
    for result in hook_results:
        output_html = ""
        if result.get("output_path"):
            output_html = f'<div><code>{html.escape(result["output_path"])}</code></div>'
        items.append(
            f"""
            <div class="hook-result hook-{html.escape(result['status'])}">
                <strong>{html.escape(result['tool'])}</strong>: {html.escape(result['message'])}
                {output_html}
            </div>
            """
        )

    return "".join(items)


ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
NMAP_PORT_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.MULTILINE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def _strip_ansi(value):
    return ANSI_ESCAPE_RE.sub("", value or "")


def _read_output_text(path):
    if not path or not os.path.exists(path):
        return ""

    with open(path, encoding="utf-8", errors="replace") as handle:
        return _strip_ansi(handle.read())


def _parse_nmap_ports(text):
    ports = []
    for match in NMAP_PORT_RE.finditer(text):
        ports.append(
            {
                "port": int(match.group(1)),
                "proto": match.group(2),
                "service": match.group(3).lower(),
                "version": match.group(4).strip(),
            }
        )
    return ports


def _parse_lynis_flags(text):
    flagged_lines = []
    interesting_tokens = ("UNSAFE", "EXPOSED", "WARNING", "DISABLED", "NONE")
    for line in text.splitlines():
        stripped = " ".join(line.split())
        if any(token in stripped for token in interesting_tokens):
            flagged_lines.append(stripped)
    return flagged_lines


def _parse_openssl_summary(text):
    protocol = None
    cipher = None
    verification_error = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Protocol  :"):
            protocol = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Cipher    :"):
            cipher = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Verification error:"):
            verification_error = stripped.split(":", 1)[1].strip()

    return {
        "protocol": protocol,
        "cipher": cipher,
        "verification_error": verification_error,
    }


def _result_paths(hook_results):
    return [result["output_path"] for result in hook_results if result.get("output_path")]


def build_requirement_assessment(requirement, hook_results):
    requirement_id = requirement["id"]
    findings = []
    evidence = []
    recommendations = []
    vulnerabilities = []
    verdict = "needs-review"

    tool_outputs = {result["tool"]: _read_output_text(result.get("output_path")) for result in hook_results}
    hook_by_tool = {result["tool"]: result for result in hook_results}
    skipped_tools = [
        f'{result["tool"]}: {result["message"]}'
        for result in hook_results
        if result.get("status") == "skipped"
    ]

    if requirement_id == "3.2.1":
        lynis_text = tool_outputs.get("lynis", "")
        flagged_lines = _parse_lynis_flags(lynis_text)
        if flagged_lines:
            verdict = "fail"
            findings.append(
                f"Lynis reported {len(flagged_lines)} hardening issues including: "
                + "; ".join(flagged_lines[:5])
            )
            vulnerabilities.append("Weak OS hardening may allow privilege escalation, service abuse, or persistence.")
            recommendations.append("Harden the exposed services and disabled protections reported by Lynis.")
        elif hook_by_tool.get("lynis", {}).get("status") == "ok":
            verdict = "pass"
            findings.append("No high-signal hardening violations were automatically extracted from the Lynis run.")
        else:
            findings.append("OS hardening could not be validated automatically.")

    elif requirement_id == "3.2.2":
        ports = _parse_nmap_ports(tool_outputs.get("nmap", ""))
        risky_services = {"telnet", "ftp", "vnc", "rsh", "rexec", "rlogin"}
        risky_ports = [port for port in ports if port["service"] in risky_services]
        if risky_ports:
            verdict = "fail"
            findings.append(
                "High-risk network services are exposed: "
                + ", ".join(f'{item["port"]}/{item["proto"]} {item["service"]}' for item in risky_ports)
            )
            vulnerabilities.append("Unnecessary exposed services increase the attack surface and remote access risk.")
        elif ports:
            verdict = "needs-review"
            findings.append(
                "Exposed services require business justification: "
                + ", ".join(f'{item["port"]}/{item["proto"]} {item["service"]}' for item in ports)
            )
        else:
            findings.append("No open services were identified by the automated Nmap scan.")

    elif requirement_id == "3.2.3":
        ports = _parse_nmap_ports(tool_outputs.get("nmap", ""))
        insecure_services = [port for port in ports if port["service"] in {"telnet", "ftp"}]
        tshark_text = tool_outputs.get("tshark", "").lower()
        plaintext_markers = [marker for marker in ("telnet", "ftp", "user ", "pass ") if marker in tshark_text]
        if insecure_services or plaintext_markers:
            verdict = "fail"
            if insecure_services:
                findings.append(
                    "Insecure legacy services were detected: "
                    + ", ".join(f'{item["port"]}/{item["proto"]} {item["service"]}' for item in insecure_services)
                )
                vulnerabilities.append("Legacy plaintext protocols can expose credentials and session data.")
            if plaintext_markers:
                findings.append(
                    "Traffic capture contained plaintext protocol indicators: "
                    + ", ".join(sorted(set(plaintext_markers)))
                )
                vulnerabilities.append("Plaintext traffic can enable credential theft and packet interception.")
        elif ports:
            verdict = "pass"
            findings.append("No Telnet or FTP exposure was detected in the sampled scan results.")
        else:
            findings.append("Protocol usage could not be confirmed from the collected evidence.")

    elif requirement_id == "3.2.4":
        cve_matches = sorted(set(CVE_RE.findall(tool_outputs.get("cve_bin_tool", ""))))
        if cve_matches:
            verdict = "fail"
            findings.append(
                f"Known vulnerabilities were identified in firmware components: {', '.join(cve_matches[:8])}"
            )
            vulnerabilities.append("Outdated components may be exploitable through publicly known CVEs.")
            if len(cve_matches) > 8:
                findings.append(f"{len(cve_matches) - 8} additional CVE entries are present in the scan output.")
        elif hook_by_tool.get("cve_bin_tool", {}).get("status") == "ok":
            verdict = "pass"
            findings.append("No CVE identifiers were automatically extracted from the component scan output.")
        else:
            findings.append("Firmware vulnerability scanning did not complete, so CVE exposure remains unverified.")

    elif requirement_id == "3.4.3":
        openssl_summary = _parse_openssl_summary(tool_outputs.get("openssl", ""))
        if openssl_summary["verification_error"]:
            verdict = "fail"
            findings.append(
                f"TLS trust validation failed during evidence collection: {openssl_summary['verification_error']}."
            )
            vulnerabilities.append("Trust failures can allow spoofed update sources or man-in-the-middle attacks.")
        elif hook_by_tool.get("openssl", {}).get("status") == "ok":
            verdict = "needs-review"
            findings.append("Transport security was observed, but update-signing logic still needs binary-level validation.")
        else:
            findings.append("No signing verification evidence was collected automatically.")

    elif requirement_id == "3.4.12":
        openssl_summary = _parse_openssl_summary(tool_outputs.get("openssl", ""))
        testssl_text = tool_outputs.get("testssl", "")
        if "Tool not found in PATH" in testssl_text:
            findings.append("`testssl.sh` was unavailable, so the TLS assessment is incomplete.")
        if openssl_summary["protocol"]:
            findings.append(
                f"Encrypted transport was observed with {openssl_summary['protocol']} and cipher {openssl_summary['cipher']}."
            )
            verdict = "pass"
            if openssl_summary["verification_error"]:
                verdict = "needs-review"
                findings.append(
                    f"Certificate validation still needs remediation: {openssl_summary['verification_error']}."
                )
                vulnerabilities.append("Improper certificate validation can weaken encrypted update delivery.")
        else:
            findings.append("No encrypted update transport was demonstrated by the collected evidence.")

    if not findings:
        if hook_results:
            if all(result.get("status") == "ok" for result in hook_results):
                verdict = "needs-review"
                findings.append("Automated evidence was collected, but this control still needs analyst interpretation.")
            else:
                findings.append("Available automation did not produce enough evidence for a control verdict.")
        else:
            verdict = "not-tested"
            findings.append("No automated checks are defined for this control. Manual auditing is required.")

    if skipped_tools:
        evidence.append("Unavailable or skipped tooling: " + "; ".join(skipped_tools))

    result_paths = _result_paths(hook_results)
    if result_paths:
        evidence.append("Collected evidence files:")
        evidence.extend(result_paths)

    if not recommendations:
        if verdict == "fail":
            recommendations.append("Review the evidence files and remediate the exposed weakness before closing this control.")
        elif verdict in {"needs-review", "not-tested"}:
            recommendations.append("Complete the manual checklist steps and confirm the result with device-specific evidence.")
        else:
            recommendations.append("Retain the captured evidence and confirm the control against the approved checklist.")

    return {
        "verdict": verdict,
        "findings": findings,
        "vulnerabilities": vulnerabilities,
        "evidence": evidence,
        "recommendations": recommendations,
    }


def render_requirement_assessment(assessment):
    verdict_map = {
        "pass": ("Pass", "verdict-pass"),
        "fail": ("Fail", "verdict-fail"),
        "needs-review": ("Needs Review", "verdict-review"),
        "not-tested": ("Not Tested", "verdict-review"),
    }
    verdict_label, verdict_class = verdict_map[assessment["verdict"]]

    findings_html = "".join(f"<li>{html.escape(item)}</li>" for item in assessment["findings"])
    vulnerabilities_html = "".join(
        f"<li>{html.escape(item)}</li>" for item in assessment["vulnerabilities"]
    )
    evidence_html = "".join(f"<li><code>{html.escape(item)}</code></li>" for item in assessment["evidence"])
    recommendation_html = "".join(f"<li>{html.escape(item)}</li>" for item in assessment["recommendations"])

    vulnerabilities_block = ""
    if assessment["vulnerabilities"]:
        vulnerabilities_block = f"""
        <div class="assessment-block">
            <strong>Vulnerabilities / Exposure</strong>
            <ul>{vulnerabilities_html}</ul>
        </div>
        """

    return f"""
    <div class="requirement-assessment">
        <div class="verdict-pill {verdict_class}">{html.escape(verdict_label)}</div>
        <div class="assessment-block">
            <strong>Reasons / Findings</strong>
            <ul>{findings_html}</ul>
        </div>
        {vulnerabilities_block}
        <div class="assessment-block">
            <strong>Evidence</strong>
            <ul>{evidence_html}</ul>
        </div>
        <div class="assessment-block">
            <strong>Next Step</strong>
            <ul>{recommendation_html}</ul>
        </div>
    </div>
    """

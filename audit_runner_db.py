import importlib
import inspect
import os
from datetime import datetime


def _group_module_selection(selected_modules):
    grouped_modules = {}

    for entry in selected_modules:
        if ":" in entry:
            module_name, item_id = entry.split(":", 1)
            grouped_modules.setdefault(module_name, {"run_full": False, "selected_checks": []})
            grouped_modules[module_name]["selected_checks"].append(item_id)
        else:
            grouped_modules.setdefault(entry, {"run_full": False, "selected_checks": []})
            grouped_modules[entry]["run_full"] = True

    return grouped_modules


def run_modules(selected_modules, args, log_callback=None):
    module_map = {
        "v2": "modules.v2.v2_checks",
        "v3": "modules.v3.v3_checks",
        "v4": "modules.v4.v4_checks",
        "v5": "modules.v5.v5_checks",
    }

    if "all" in selected_modules:
        selected_modules = ["v2", "v3", "v4", "v5"]

    grouped_modules = _group_module_selection(selected_modules)
    report_sections = []

    for mod, selection in grouped_modules.items():
        if mod not in module_map:
            continue

        if log_callback:
            if selection["run_full"] or not selection["selected_checks"]:
                log_callback(f"Running {mod} module...")
            else:
                log_callback(f"Running {mod} module for checks: {', '.join(selection['selected_checks'])}")

        module = importlib.import_module(module_map[mod])
        runner = getattr(module, f"run_{mod}")
        signature = inspect.signature(runner)

        call_kwargs = {}
        if "selected_checks" in signature.parameters:
            call_kwargs["selected_checks"] = None if selection["run_full"] else selection["selected_checks"]
        if "log_callback" in signature.parameters:
            call_kwargs["log_callback"] = log_callback

        section_html = runner(args, **call_kwargs) if call_kwargs else runner(args)

        if section_html:
            report_sections.append(section_html)

    final_report = f"""
    <html>
    <body>
    <h1>IoT Audit Report</h1>
    <p>Date: {datetime.now()}</p>
    {''.join(report_sections)}
    </body>
    </html>
    """

    report_path = os.path.join(args["outdir"], "final_report.html")

    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write(final_report)

    return report_path

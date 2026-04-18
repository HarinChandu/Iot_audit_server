import os
import threading
import uuid

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from audit_runner_db import run_modules
from db import append_log, create_job, get_job, init_db, update_job, validate_user
from modules.v2.v2_checks import V2_REQUIREMENTS
from modules.v3.v3_checks import V3_REQUIREMENTS
from modules.v4.v4_checks import V4_REQUIREMENTS

app = Flask(__name__)
app.secret_key = "supersecretkey"
init_db()

OUTPUT_DIR = "evidence"


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if validate_user(request.form["username"], request.form["password"]):
            session["user"] = request.form["username"]
            return redirect(url_for("dashboard"))
        return "Invalid credentials"
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        v2_requirements=V2_REQUIREMENTS,
        v3_requirements=V3_REQUIREMENTS,
        v4_requirements=V4_REQUIREMENTS,
    )


def run_audit_background(job_id):
    try:
        job = get_job(job_id)
        if not job:
            return

        args = {
            "ip": job["device_ip"],
            "user": job["device_user"],
            "password": job["device_password"],
            "outdir": os.path.join(OUTPUT_DIR, job_id),
        }
        args.update(job.get("job_params", {}))

        os.makedirs(args["outdir"], exist_ok=True)
        update_job(job_id, status="Running")
        append_log(job_id, "Audit started")

        report_path = run_modules(
            job["selected_modules"],
            args,
            lambda message: append_log(job_id, message),
        )

        append_log(job_id, "Audit completed")
        update_job(job_id, status="Completed", report_path=report_path, error_message=None)
    except Exception as exc:
        append_log(job_id, f"Error: {exc}")
        update_job(job_id, status="Failed", error_message=str(exc))


@app.route("/run_audit", methods=["POST"])
def run_audit():
    if "user" not in session:
        return redirect(url_for("login"))

    modules = request.form.getlist("modules")
    job_id = str(uuid.uuid4())[:8]
    outdir = os.path.join(OUTPUT_DIR, job_id)
    upload_dir = os.path.join(outdir, "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    firmware_upload = request.files.get("firmware_file")
    firmware_path = request.form.get("firmware_path", "").strip()

    if firmware_upload and firmware_upload.filename:
        filename = secure_filename(firmware_upload.filename)
        saved_path = os.path.join(upload_dir, filename)
        firmware_upload.save(saved_path)
        firmware_path = saved_path

    args = {
        "ip": request.form["ip"],
        "user": request.form["user"],
        "password": request.form["password"],
        "outdir": outdir,
        "firmware_path": firmware_path,
        "api_endpoint": request.form.get("api_endpoint", ""),
        "update_server": request.form.get("update_server", ""),
        "mqtt_host": request.form.get("mqtt_host", ""),
        "network_interface": request.form.get("network_interface", ""),
        "bluetooth_adapter": request.form.get("bluetooth_adapter", ""),
        "capture_seconds": request.form.get("capture_seconds", "10"),
        "tls_port": request.form.get("tls_port", "443"),
    }

    create_job(job_id, session["user"], modules, args)
    threading.Thread(target=run_audit_background, args=(job_id,), daemon=True).start()

    return redirect(url_for("progress", job_id=job_id))


@app.route("/progress/<job_id>")
def progress(job_id):
    return render_template("progress.html", job_id=job_id)


@app.route("/status/<job_id>")
def status(job_id):
    job = get_job(job_id)
    if not job:
        return jsonify({"status": "Unknown", "logs": ["Job not found"], "report": None}), 404

    return jsonify(
        {
            "job_id": job["job_id"],
            "status": job["status"],
            "logs": job.get("logs", []),
            "report": job.get("report_path"),
            "error": job.get("error_message"),
        }
    )


@app.route("/report")
def report():
    return render_template("report.html", path=request.args.get("path"))


@app.route("/download")
def download():
    path = request.args.get("path")
    if path and os.path.exists(path):
        return send_file(path, as_attachment=True)
    return "No report"


@app.route("/raw_report")
def raw_report():
    path = request.args.get("path")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as report_file:
            return report_file.read()
    return "<h3>No report available</h3>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

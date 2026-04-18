import json
import os
from contextlib import contextmanager
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import check_password_hash, generate_password_hash


def _load_local_env():
    env_path = Path(__file__).with_name(".env")
    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


_load_local_env()


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "iot_audit"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "1234"),
}


@contextmanager
def get_connection():
    connection = psycopg2.connect(**DB_CONFIG)
    try:
        yield connection
    finally:
        connection.close()


def init_db():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_jobs (
                    job_id VARCHAR(32) PRIMARY KEY,
                    created_by VARCHAR(100) NOT NULL,
                    device_ip VARCHAR(100) NOT NULL,
                    device_user VARCHAR(100) NOT NULL,
                    device_password TEXT NOT NULL,
                    args_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    job_params JSONB NOT NULL DEFAULT '{}'::jsonb,
                    selected_modules JSONB NOT NULL,
                    status VARCHAR(30) NOT NULL,
                    logs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    report_path TEXT,
                    error_message TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            audit_job_migrations = (
                "ADD COLUMN IF NOT EXISTS created_by VARCHAR(100)",
                "ADD COLUMN IF NOT EXISTS device_ip VARCHAR(100)",
                "ADD COLUMN IF NOT EXISTS device_user VARCHAR(100)",
                "ADD COLUMN IF NOT EXISTS device_password TEXT",
                "ADD COLUMN IF NOT EXISTS args_json JSONB NOT NULL DEFAULT '{}'::jsonb",
                "ADD COLUMN IF NOT EXISTS job_params JSONB NOT NULL DEFAULT '{}'::jsonb",
                "ADD COLUMN IF NOT EXISTS selected_modules JSONB NOT NULL DEFAULT '[]'::jsonb",
                "ADD COLUMN IF NOT EXISTS status VARCHAR(30) NOT NULL DEFAULT 'Queued'",
                "ADD COLUMN IF NOT EXISTS logs JSONB NOT NULL DEFAULT '[]'::jsonb",
                "ADD COLUMN IF NOT EXISTS report_path TEXT",
                "ADD COLUMN IF NOT EXISTS error_message TEXT",
                "ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
                "ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP",
            )
            for migration in audit_job_migrations:
                cursor.execute(f"ALTER TABLE audit_jobs {migration}")

            cursor.execute(
                """
                UPDATE audit_jobs
                SET created_by = COALESCE(created_by, 'unknown'),
                    device_ip = COALESCE(device_ip, ''),
                    device_user = COALESCE(device_user, ''),
                    device_password = COALESCE(device_password, ''),
                    args_json = COALESCE(args_json, job_params, '{}'::jsonb),
                    selected_modules = COALESCE(selected_modules, '[]'::jsonb),
                    status = COALESCE(status, 'Queued'),
                    logs = COALESCE(logs, '[]'::jsonb),
                    created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
                    updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)
                """
            )
            cursor.execute(
                """
                UPDATE audit_jobs
                SET job_params = args_json
                WHERE job_params = '{}'::jsonb
                  AND args_json IS NOT NULL
                  AND args_json <> '{}'::jsonb
                """
            )
            cursor.execute("ALTER TABLE audit_jobs ALTER COLUMN created_by SET NOT NULL")
            cursor.execute("ALTER TABLE audit_jobs ALTER COLUMN device_ip SET NOT NULL")
            cursor.execute("ALTER TABLE audit_jobs ALTER COLUMN device_user SET NOT NULL")
            cursor.execute("ALTER TABLE audit_jobs ALTER COLUMN device_password SET NOT NULL")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS app_users (
                    username VARCHAR(100) PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        connection.commit()
    ensure_default_user()


def ensure_default_user():
    username = os.getenv("APP_ADMIN_USER", "admin")
    password = os.getenv("APP_ADMIN_PASSWORD", "admin123")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT username FROM app_users WHERE username = %s", (username,))
            existing_user = cursor.fetchone()

            if not existing_user:
                cursor.execute(
                    """
                    INSERT INTO app_users (username, password_hash)
                    VALUES (%s, %s)
                    """,
                    (username, generate_password_hash(password)),
                )
        connection.commit()


def create_job(job_id, created_by, modules, args):
    job_params = {
        "firmware_path": args.get("firmware_path", ""),
        "api_endpoint": args.get("api_endpoint", ""),
        "update_server": args.get("update_server", ""),
        "mqtt_host": args.get("mqtt_host", ""),
        "network_interface": args.get("network_interface", ""),
        "bluetooth_adapter": args.get("bluetooth_adapter", ""),
        "capture_seconds": args.get("capture_seconds", "10"),
        "tls_port": args.get("tls_port", "443"),
    }

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO audit_jobs (
                    job_id,
                    created_by,
                    device_ip,
                    device_user,
                    device_password,
                    args_json,
                    job_params,
                    selected_modules,
                    status,
                    logs
                )
                VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s::jsonb)
                """,
                (
                    job_id,
                    created_by,
                    args["ip"],
                    args["user"],
                    args["password"],
                    json.dumps(job_params),
                    json.dumps(job_params),
                    json.dumps(modules),
                    "Queued",
                    json.dumps(["Job created"]),
                ),
            )
        connection.commit()


def get_job(job_id):
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM audit_jobs WHERE job_id = %s", (job_id,))
            row = cursor.fetchone()

    if not row:
        return None

    row["logs"] = row.get("logs") or []
    row["job_params"] = row.get("job_params") or {}
    row["selected_modules"] = row.get("selected_modules") or []
    return dict(row)


def update_job(job_id, **fields):
    if not fields:
        return

    assignments = []
    values = []

    for key, value in fields.items():
        if key in {"logs", "selected_modules"}:
            assignments.append(f"{key} = %s::jsonb")
            values.append(json.dumps(value))
        else:
            assignments.append(f"{key} = %s")
            values.append(value)

    assignments.append("updated_at = CURRENT_TIMESTAMP")
    values.append(job_id)

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                UPDATE audit_jobs
                SET {", ".join(assignments)}
                WHERE job_id = %s
                """,
                values,
            )
        connection.commit()


def append_log(job_id, message):
    job = get_job(job_id)
    if not job:
        return

    logs = job.get("logs", [])
    logs.append(message)
    update_job(job_id, logs=logs)


def validate_user(username, password):
    with get_connection() as connection:
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT username, password_hash FROM app_users WHERE username = %s",
                (username,),
            )
            user = cursor.fetchone()

    if not user:
        return False

    return check_password_hash(user["password_hash"], password)


def create_user(username, password):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO app_users (username, password_hash)
                VALUES (%s, %s)
                ON CONFLICT (username) DO UPDATE
                SET password_hash = EXCLUDED.password_hash,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (username, generate_password_hash(password)),
            )
        connection.commit()

CREATE TABLE IF NOT EXISTS audit_jobs (
    job_id VARCHAR(32) PRIMARY KEY,
    created_by VARCHAR(100) NOT NULL,
    device_ip VARCHAR(100) NOT NULL,
    device_user VARCHAR(100) NOT NULL,
    device_password TEXT NOT NULL,
    job_params JSONB NOT NULL DEFAULT '{}'::jsonb,
    selected_modules JSONB NOT NULL,
    status VARCHAR(30) NOT NULL,
    logs JSONB NOT NULL DEFAULT '[]'::jsonb,
    report_path TEXT,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_users (
    username VARCHAR(100) PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
